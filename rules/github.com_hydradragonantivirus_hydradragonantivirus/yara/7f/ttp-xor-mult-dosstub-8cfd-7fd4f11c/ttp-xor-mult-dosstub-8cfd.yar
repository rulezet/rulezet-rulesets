rule TTP_XOR_MULT_DOSStub_8cfd {
  strings:
    $key_8cfd = { d8 95 [2] ac 8d [2] eb 8f [2] ac 9e [2] e2 92 [2] ee 98 [2] f9 93 [2] e2 dd [2] df }

  condition:
    any of them
}