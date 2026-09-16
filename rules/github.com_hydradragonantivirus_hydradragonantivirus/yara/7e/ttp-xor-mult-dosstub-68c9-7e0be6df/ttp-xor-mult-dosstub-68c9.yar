rule TTP_XOR_MULT_DOSStub_68c9 {
  strings:
    $key_68c9 = { 3c a1 [2] 48 b9 [2] 0f bb [2] 48 aa [2] 06 a6 [2] 0a ac [2] 1d a7 [2] 06 e9 [2] 3b }

  condition:
    any of them
}