rule TTP_XOR_MULT_DOSStub_706c {
  strings:
    $key_706c = { 24 04 [2] 50 1c [2] 17 1e [2] 50 0f [2] 1e 03 [2] 12 09 [2] 05 02 [2] 1e 4c [2] 23 }

  condition:
    any of them
}