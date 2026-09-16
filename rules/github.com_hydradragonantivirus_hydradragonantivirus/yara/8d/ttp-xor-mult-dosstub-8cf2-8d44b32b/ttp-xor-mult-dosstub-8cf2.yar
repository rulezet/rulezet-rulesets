rule TTP_XOR_MULT_DOSStub_8cf2 {
  strings:
    $key_8cf2 = { d8 9a [2] ac 82 [2] eb 80 [2] ac 91 [2] e2 9d [2] ee 97 [2] f9 9c [2] e2 d2 [2] df }

  condition:
    any of them
}