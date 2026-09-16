rule TTP_XOR_MULT_DOSStub_86cd {
  strings:
    $key_86cd = { d2 a5 [2] a6 bd [2] e1 bf [2] a6 ae [2] e8 a2 [2] e4 a8 [2] f3 a3 [2] e8 ed [2] d5 }

  condition:
    any of them
}