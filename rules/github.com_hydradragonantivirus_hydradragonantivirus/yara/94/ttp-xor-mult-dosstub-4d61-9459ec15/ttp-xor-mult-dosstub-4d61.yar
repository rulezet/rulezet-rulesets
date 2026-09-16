rule TTP_XOR_MULT_DOSStub_4d61 {
  strings:
    $key_4d61 = { 19 09 [2] 6d 11 [2] 2a 13 [2] 6d 02 [2] 23 0e [2] 2f 04 [2] 38 0f [2] 23 41 [2] 1e }

  condition:
    any of them
}