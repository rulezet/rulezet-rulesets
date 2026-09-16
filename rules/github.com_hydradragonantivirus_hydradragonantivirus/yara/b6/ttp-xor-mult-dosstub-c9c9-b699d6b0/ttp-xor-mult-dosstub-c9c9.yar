rule TTP_XOR_MULT_DOSStub_c9c9 {
  strings:
    $key_c9c9 = { 9d a1 [2] e9 b9 [2] ae bb [2] e9 aa [2] a7 a6 [2] ab ac [2] bc a7 [2] a7 e9 [2] 9a }

  condition:
    any of them
}