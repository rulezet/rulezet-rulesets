rule TTP_XOR_MULT_DOSStub_65ee {
  strings:
    $key_65ee = { 31 86 [2] 45 9e [2] 02 9c [2] 45 8d [2] 0b 81 [2] 07 8b [2] 10 80 [2] 0b ce [2] 36 }

  condition:
    any of them
}