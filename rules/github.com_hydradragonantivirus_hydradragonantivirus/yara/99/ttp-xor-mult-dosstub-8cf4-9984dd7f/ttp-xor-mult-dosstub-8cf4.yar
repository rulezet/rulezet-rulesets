rule TTP_XOR_MULT_DOSStub_8cf4 {
  strings:
    $key_8cf4 = { d8 9c [2] ac 84 [2] eb 86 [2] ac 97 [2] e2 9b [2] ee 91 [2] f9 9a [2] e2 d4 [2] df }

  condition:
    any of them
}