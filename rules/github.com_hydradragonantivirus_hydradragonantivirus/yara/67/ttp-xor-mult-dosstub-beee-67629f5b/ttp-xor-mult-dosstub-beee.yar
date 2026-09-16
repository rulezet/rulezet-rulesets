rule TTP_XOR_MULT_DOSStub_beee {
  strings:
    $key_beee = { ea 86 [2] 9e 9e [2] d9 9c [2] 9e 8d [2] d0 81 [2] dc 8b [2] cb 80 [2] d0 ce [2] ed }

  condition:
    any of them
}