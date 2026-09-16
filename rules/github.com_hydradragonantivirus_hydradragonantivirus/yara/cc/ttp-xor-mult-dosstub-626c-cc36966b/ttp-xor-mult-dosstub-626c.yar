rule TTP_XOR_MULT_DOSStub_626c {
  strings:
    $key_626c = { 36 04 [2] 42 1c [2] 05 1e [2] 42 0f [2] 0c 03 [2] 00 09 [2] 17 02 [2] 0c 4c [2] 31 }

  condition:
    any of them
}