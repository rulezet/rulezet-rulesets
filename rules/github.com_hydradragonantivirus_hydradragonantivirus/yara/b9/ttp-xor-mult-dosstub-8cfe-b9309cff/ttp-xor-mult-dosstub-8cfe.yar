rule TTP_XOR_MULT_DOSStub_8cfe {
  strings:
    $key_8cfe = { d8 96 [2] ac 8e [2] eb 8c [2] ac 9d [2] e2 91 [2] ee 9b [2] f9 90 [2] e2 de [2] df }

  condition:
    any of them
}