rule TTP_XOR_MULT_DOSStub_146c {
  strings:
    $key_146c = { 40 04 [2] 34 1c [2] 73 1e [2] 34 0f [2] 7a 03 [2] 76 09 [2] 61 02 [2] 7a 4c [2] 47 }

  condition:
    any of them
}