rule TTP_XOR_MULT_DOSStub_58c5 {
  strings:
    $key_58c5 = { 0c ad [2] 78 b5 [2] 3f b7 [2] 78 a6 [2] 36 aa [2] 3a a0 [2] 2d ab [2] 36 e5 [2] 0b }

  condition:
    any of them
}