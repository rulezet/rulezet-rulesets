rule TTP_XOR_MULT_DOSStub_cdee {
  strings:
    $key_cdee = { 99 86 [2] ed 9e [2] aa 9c [2] ed 8d [2] a3 81 [2] af 8b [2] b8 80 [2] a3 ce [2] 9e }

  condition:
    any of them
}