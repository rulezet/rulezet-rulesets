rule TTP_XOR_MULT_DOSStub_84cd {
  strings:
    $key_84cd = { d0 a5 [2] a4 bd [2] e3 bf [2] a4 ae [2] ea a2 [2] e6 a8 [2] f1 a3 [2] ea ed [2] d7 }

  condition:
    any of them
}