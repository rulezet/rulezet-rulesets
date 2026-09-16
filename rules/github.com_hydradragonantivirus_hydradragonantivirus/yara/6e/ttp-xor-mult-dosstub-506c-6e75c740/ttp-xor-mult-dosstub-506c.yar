rule TTP_XOR_MULT_DOSStub_506c {
  strings:
    $key_506c = { 04 04 [2] 70 1c [2] 37 1e [2] 70 0f [2] 3e 03 [2] 32 09 [2] 25 02 [2] 3e 4c [2] 03 }

  condition:
    any of them
}