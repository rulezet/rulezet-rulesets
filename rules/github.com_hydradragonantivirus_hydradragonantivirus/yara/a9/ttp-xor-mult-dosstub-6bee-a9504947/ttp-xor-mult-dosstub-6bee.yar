rule TTP_XOR_MULT_DOSStub_6bee {
  strings:
    $key_6bee = { 3f 86 [2] 4b 9e [2] 0c 9c [2] 4b 8d [2] 05 81 [2] 09 8b [2] 1e 80 [2] 05 ce [2] 38 }

  condition:
    any of them
}