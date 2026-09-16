rule TTP_XOR_MULT_DOSStub_eeee {
  strings:
    $key_eeee = { ba 86 [2] ce 9e [2] 89 9c [2] ce 8d [2] 80 81 [2] 8c 8b [2] 9b 80 [2] 80 ce [2] bd }

  condition:
    any of them
}