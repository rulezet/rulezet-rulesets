rule TTP_XOR_MULT_DOSStub_1e61 {
  strings:
    $key_1e61 = { 4a 09 [2] 3e 11 [2] 79 13 [2] 3e 02 [2] 70 0e [2] 7c 04 [2] 6b 0f [2] 70 41 [2] 4d }

  condition:
    any of them
}