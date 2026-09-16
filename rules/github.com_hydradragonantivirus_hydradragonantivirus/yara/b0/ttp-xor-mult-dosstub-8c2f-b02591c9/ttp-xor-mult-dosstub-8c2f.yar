rule TTP_XOR_MULT_DOSStub_8c2f {
  strings:
    $key_8c2f = { d8 47 [2] ac 5f [2] eb 5d [2] ac 4c [2] e2 40 [2] ee 4a [2] f9 41 [2] e2 0f [2] df }

  condition:
    any of them
}