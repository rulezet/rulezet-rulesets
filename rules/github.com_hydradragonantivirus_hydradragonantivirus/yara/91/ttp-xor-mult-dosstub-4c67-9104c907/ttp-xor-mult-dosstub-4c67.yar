rule TTP_XOR_MULT_DOSStub_4c67 {
  strings:
    $key_4c67 = { 18 0f [2] 6c 17 [2] 2b 15 [2] 6c 04 [2] 22 08 [2] 2e 02 [2] 39 09 [2] 22 47 [2] 1f }

  condition:
    any of them
}