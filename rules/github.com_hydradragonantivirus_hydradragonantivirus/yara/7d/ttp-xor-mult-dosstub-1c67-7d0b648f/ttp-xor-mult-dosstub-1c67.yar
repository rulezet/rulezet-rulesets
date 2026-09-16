rule TTP_XOR_MULT_DOSStub_1c67 {
  strings:
    $key_1c67 = { 48 0f [2] 3c 17 [2] 7b 15 [2] 3c 04 [2] 72 08 [2] 7e 02 [2] 69 09 [2] 72 47 [2] 4f }

  condition:
    any of them
}