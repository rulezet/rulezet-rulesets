rule TTP_XOR_MULT_DOSStub_e8c9 {
  strings:
    $key_e8c9 = { bc a1 [2] c8 b9 [2] 8f bb [2] c8 aa [2] 86 a6 [2] 8a ac [2] 9d a7 [2] 86 e9 [2] bb }

  condition:
    any of them
}