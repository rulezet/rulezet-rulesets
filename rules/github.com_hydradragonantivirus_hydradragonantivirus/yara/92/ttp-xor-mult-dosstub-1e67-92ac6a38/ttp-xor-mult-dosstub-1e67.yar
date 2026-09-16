rule TTP_XOR_MULT_DOSStub_1e67 {
  strings:
    $key_1e67 = { 4a 0f [2] 3e 17 [2] 79 15 [2] 3e 04 [2] 70 08 [2] 7c 02 [2] 6b 09 [2] 70 47 [2] 4d }

  condition:
    any of them
}