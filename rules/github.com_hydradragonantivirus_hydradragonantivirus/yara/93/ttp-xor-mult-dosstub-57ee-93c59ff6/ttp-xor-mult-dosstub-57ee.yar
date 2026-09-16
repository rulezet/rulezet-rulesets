rule TTP_XOR_MULT_DOSStub_57ee {
  strings:
    $key_57ee = { 03 86 [2] 77 9e [2] 30 9c [2] 77 8d [2] 39 81 [2] 35 8b [2] 22 80 [2] 39 ce [2] 04 }

  condition:
    any of them
}