rule TTP_XOR_MULT_DOSStub_29ee {
  strings:
    $key_29ee = { 7d 86 [2] 09 9e [2] 4e 9c [2] 09 8d [2] 47 81 [2] 4b 8b [2] 5c 80 [2] 47 ce [2] 7a }

  condition:
    any of them
}