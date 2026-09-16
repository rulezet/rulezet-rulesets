rule TTP_XOR_MULT_DOSStub_fcee {
  strings:
    $key_fcee = { a8 86 [2] dc 9e [2] 9b 9c [2] dc 8d [2] 92 81 [2] 9e 8b [2] 89 80 [2] 92 ce [2] af }

  condition:
    any of them
}