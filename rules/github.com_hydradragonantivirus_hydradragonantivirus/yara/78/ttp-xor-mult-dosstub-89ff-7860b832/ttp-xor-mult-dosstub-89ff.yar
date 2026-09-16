rule TTP_XOR_MULT_DOSStub_89ff {
  strings:
    $key_89ff = { dd 97 [2] a9 8f [2] ee 8d [2] a9 9c [2] e7 90 [2] eb 9a [2] fc 91 [2] e7 df [2] da }

  condition:
    any of them
}