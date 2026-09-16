rule TTP_XOR_MULT_DOSStub_94ce {
  strings:
    $key_94ce = { c0 a6 [2] b4 be [2] f3 bc [2] b4 ad [2] fa a1 [2] f6 ab [2] e1 a0 [2] fa ee [2] c7 }

  condition:
    any of them
}