rule TTP_XOR_MULT_DOSStub_7267 {
  strings:
    $key_7267 = { 26 0f [2] 52 17 [2] 15 15 [2] 52 04 [2] 1c 08 [2] 10 02 [2] 07 09 [2] 1c 47 [2] 21 }

  condition:
    any of them
}