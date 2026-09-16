rule TTP_XOR_MULT_DOSStub_8cef {
  strings:
    $key_8cef = { d8 87 [2] ac 9f [2] eb 9d [2] ac 8c [2] e2 80 [2] ee 8a [2] f9 81 [2] e2 cf [2] df }

  condition:
    any of them
}