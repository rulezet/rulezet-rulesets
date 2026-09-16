rule TTP_XOR_MULT_DOSStub_4fee {
  strings:
    $key_4fee = { 1b 86 [2] 6f 9e [2] 28 9c [2] 6f 8d [2] 21 81 [2] 2d 8b [2] 3a 80 [2] 21 ce [2] 1c }

  condition:
    any of them
}