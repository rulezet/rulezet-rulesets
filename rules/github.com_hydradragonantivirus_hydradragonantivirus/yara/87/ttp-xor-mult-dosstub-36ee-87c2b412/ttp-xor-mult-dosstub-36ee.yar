rule TTP_XOR_MULT_DOSStub_36ee {
  strings:
    $key_36ee = { 62 86 [2] 16 9e [2] 51 9c [2] 16 8d [2] 58 81 [2] 54 8b [2] 43 80 [2] 58 ce [2] 65 }

  condition:
    any of them
}