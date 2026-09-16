rule TTP_XOR_MULT_DOSStub_9bed {
  strings:
    $key_9bed = { cf 85 [2] bb 9d [2] fc 9f [2] bb 8e [2] f5 82 [2] f9 88 [2] ee 83 [2] f5 cd [2] c8 }

  condition:
    any of them
}