rule TTP_XOR_MULT_DOSStub_1fee {
  strings:
    $key_1fee = { 4b 86 [2] 3f 9e [2] 78 9c [2] 3f 8d [2] 71 81 [2] 7d 8b [2] 6a 80 [2] 71 ce [2] 4c }

  condition:
    any of them
}