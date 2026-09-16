rule TTP_XOR_MULT_DOSStub_8cea {
  strings:
    $key_8cea = { d8 82 [2] ac 9a [2] eb 98 [2] ac 89 [2] e2 85 [2] ee 8f [2] f9 84 [2] e2 ca [2] df }

  condition:
    any of them
}