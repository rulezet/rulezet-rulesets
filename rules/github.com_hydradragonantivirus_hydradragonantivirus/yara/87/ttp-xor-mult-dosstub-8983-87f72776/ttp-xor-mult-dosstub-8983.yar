rule TTP_XOR_MULT_DOSStub_8983 {
  strings:
    $key_8983 = { dd eb [2] a9 f3 [2] ee f1 [2] a9 e0 [2] e7 ec [2] eb e6 [2] fc ed [2] e7 a3 [2] da }

  condition:
    any of them
}