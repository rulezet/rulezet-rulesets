rule TTP_XOR_MULT_DOSStub_9bfd {
  strings:
    $key_9bfd = { cf 95 [2] bb 8d [2] fc 8f [2] bb 9e [2] f5 92 [2] f9 98 [2] ee 93 [2] f5 dd [2] c8 }

  condition:
    any of them
}