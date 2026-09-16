rule TTP_XOR_MULT_DOSStub_98cc {
  strings:
    $key_98cc = { cc a4 [2] b8 bc [2] ff be [2] b8 af [2] f6 a3 [2] fa a9 [2] ed a2 [2] f6 ec [2] cb }

  condition:
    any of them
}