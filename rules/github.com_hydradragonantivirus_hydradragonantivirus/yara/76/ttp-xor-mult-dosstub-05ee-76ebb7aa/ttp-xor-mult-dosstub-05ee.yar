rule TTP_XOR_MULT_DOSStub_05ee {
  strings:
    $key_05ee = { 51 86 [2] 25 9e [2] 62 9c [2] 25 8d [2] 6b 81 [2] 67 8b [2] 70 80 [2] 6b ce [2] 56 }

  condition:
    any of them
}