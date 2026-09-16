rule TTP_XOR_MULT_DOSStub_48c5 {
  strings:
    $key_48c5 = { 1c ad [2] 68 b5 [2] 2f b7 [2] 68 a6 [2] 26 aa [2] 2a a0 [2] 3d ab [2] 26 e5 [2] 1b }

  condition:
    any of them
}