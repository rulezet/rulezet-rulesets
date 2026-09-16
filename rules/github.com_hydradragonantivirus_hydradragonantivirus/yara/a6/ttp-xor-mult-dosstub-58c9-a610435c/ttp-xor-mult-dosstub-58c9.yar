rule TTP_XOR_MULT_DOSStub_58c9 {
  strings:
    $key_58c9 = { 0c a1 [2] 78 b9 [2] 3f bb [2] 78 aa [2] 36 a6 [2] 3a ac [2] 2d a7 [2] 36 e9 [2] 0b }

  condition:
    any of them
}