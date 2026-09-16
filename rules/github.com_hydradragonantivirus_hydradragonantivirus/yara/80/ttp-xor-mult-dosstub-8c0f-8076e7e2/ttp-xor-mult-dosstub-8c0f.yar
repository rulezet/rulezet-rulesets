rule TTP_XOR_MULT_DOSStub_8c0f {
  strings:
    $key_8c0f = { d8 67 [2] ac 7f [2] eb 7d [2] ac 6c [2] e2 60 [2] ee 6a [2] f9 61 [2] e2 2f [2] df }

  condition:
    any of them
}