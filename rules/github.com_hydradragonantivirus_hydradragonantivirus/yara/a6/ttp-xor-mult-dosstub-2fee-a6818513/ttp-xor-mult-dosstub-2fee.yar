rule TTP_XOR_MULT_DOSStub_2fee {
  strings:
    $key_2fee = { 7b 86 [2] 0f 9e [2] 48 9c [2] 0f 8d [2] 41 81 [2] 4d 8b [2] 5a 80 [2] 41 ce [2] 7c }

  condition:
    any of them
}