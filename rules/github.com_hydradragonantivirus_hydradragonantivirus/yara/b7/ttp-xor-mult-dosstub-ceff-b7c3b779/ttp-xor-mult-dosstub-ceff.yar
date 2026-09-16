rule TTP_XOR_MULT_DOSStub_ceff {
  strings:
    $key_ceff = { 9a 97 [2] ee 8f [2] a9 8d [2] ee 9c [2] a0 90 [2] ac 9a [2] bb 91 [2] a0 df [2] 9d }

  condition:
    any of them
}