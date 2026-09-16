rule TTP_XOR_MULT_DOSStub_38c9 {
  strings:
    $key_38c9 = { 6c a1 [2] 18 b9 [2] 5f bb [2] 18 aa [2] 56 a6 [2] 5a ac [2] 4d a7 [2] 56 e9 [2] 6b }

  condition:
    any of them
}