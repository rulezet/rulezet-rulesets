rule TTP_XOR_MULT_DOSStub_546c {
  strings:
    $key_546c = { 00 04 [2] 74 1c [2] 33 1e [2] 74 0f [2] 3a 03 [2] 36 09 [2] 21 02 [2] 3a 4c [2] 07 }

  condition:
    any of them
}