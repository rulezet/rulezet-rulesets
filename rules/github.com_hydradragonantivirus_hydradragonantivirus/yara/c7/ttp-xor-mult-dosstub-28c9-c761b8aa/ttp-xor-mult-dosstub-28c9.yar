rule TTP_XOR_MULT_DOSStub_28c9 {
  strings:
    $key_28c9 = { 7c a1 [2] 08 b9 [2] 4f bb [2] 08 aa [2] 46 a6 [2] 4a ac [2] 5d a7 [2] 46 e9 [2] 7b }

  condition:
    any of them
}