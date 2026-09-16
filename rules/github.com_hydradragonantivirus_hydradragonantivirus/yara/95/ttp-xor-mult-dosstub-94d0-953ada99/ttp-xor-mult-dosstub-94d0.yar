rule TTP_XOR_MULT_DOSStub_94d0 {
  strings:
    $key_94d0 = { c0 b8 [2] b4 a0 [2] f3 a2 [2] b4 b3 [2] fa bf [2] f6 b5 [2] e1 be [2] fa f0 [2] c7 }

  condition:
    any of them
}