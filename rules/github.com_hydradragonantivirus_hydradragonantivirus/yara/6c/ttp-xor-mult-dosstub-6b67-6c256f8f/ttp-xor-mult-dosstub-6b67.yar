rule TTP_XOR_MULT_DOSStub_6b67 {
  strings:
    $key_6b67 = { 3f 0f [2] 4b 17 [2] 0c 15 [2] 4b 04 [2] 05 08 [2] 09 02 [2] 1e 09 [2] 05 47 [2] 38 }

  condition:
    any of them
}