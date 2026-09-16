rule TTP_XOR_MULT_DOSStub_68c5 {
  strings:
    $key_68c5 = { 3c ad [2] 48 b5 [2] 0f b7 [2] 48 a6 [2] 06 aa [2] 0a a0 [2] 1d ab [2] 06 e5 [2] 3b }

  condition:
    any of them
}