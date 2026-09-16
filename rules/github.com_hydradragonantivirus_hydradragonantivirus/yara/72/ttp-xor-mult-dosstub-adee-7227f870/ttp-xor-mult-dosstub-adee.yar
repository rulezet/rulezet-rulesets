rule TTP_XOR_MULT_DOSStub_adee {
  strings:
    $key_adee = { f9 86 [2] 8d 9e [2] ca 9c [2] 8d 8d [2] c3 81 [2] cf 8b [2] d8 80 [2] c3 ce [2] fe }

  condition:
    any of them
}