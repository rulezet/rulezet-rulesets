rule TTP_XOR_MULT_DOSStub_9c88 {
  strings:
    $key_9c88 = { c8 e0 [2] bc f8 [2] fb fa [2] bc eb [2] f2 e7 [2] fe ed [2] e9 e6 [2] f2 a8 [2] cf }

  condition:
    any of them
}