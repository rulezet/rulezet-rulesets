rule TTP_XOR_MULT_DOSStub_5fee {
  strings:
    $key_5fee = { 0b 86 [2] 7f 9e [2] 38 9c [2] 7f 8d [2] 31 81 [2] 3d 8b [2] 2a 80 [2] 31 ce [2] 0c }

  condition:
    any of them
}