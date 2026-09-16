rule TTP_XOR_MULT_DOSStub_3c50 {
  strings:
    $key_3c50 = { 68 38 [2] 1c 20 [2] 5b 22 [2] 1c 33 [2] 52 3f [2] 5e 35 [2] 49 3e [2] 52 70 [2] 6f }

  condition:
    any of them
}