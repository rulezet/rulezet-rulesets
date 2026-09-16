rule TTP_XOR_MULT_DOSStub_8c8e {
  strings:
    $key_8c8e = { d8 e6 [2] ac fe [2] eb fc [2] ac ed [2] e2 e1 [2] ee eb [2] f9 e0 [2] e2 ae [2] df }

  condition:
    any of them
}