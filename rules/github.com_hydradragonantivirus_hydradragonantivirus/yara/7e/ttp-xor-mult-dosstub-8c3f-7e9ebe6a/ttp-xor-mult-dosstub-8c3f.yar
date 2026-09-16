rule TTP_XOR_MULT_DOSStub_8c3f {
  strings:
    $key_8c3f = { d8 57 [2] ac 4f [2] eb 4d [2] ac 5c [2] e2 50 [2] ee 5a [2] f9 51 [2] e2 1f [2] df }

  condition:
    any of them
}