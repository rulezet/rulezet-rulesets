rule TTP_XOR_MULT_DOSStub_ffee {
  strings:
    $key_ffee = { ab 86 [2] df 9e [2] 98 9c [2] df 8d [2] 91 81 [2] 9d 8b [2] 8a 80 [2] 91 ce [2] ac }

  condition:
    any of them
}