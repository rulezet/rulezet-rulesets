rule TTP_XOR_MULT_DOSStub_8cff {
  strings:
    $key_8cff = { d8 97 [2] ac 8f [2] eb 8d [2] ac 9c [2] e2 90 [2] ee 9a [2] f9 91 [2] e2 df [2] df }

  condition:
    any of them
}