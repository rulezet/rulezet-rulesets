rule TTP_XOR_MULT_DOSStub_989c {
  strings:
    $key_989c = { cc f4 [2] b8 ec [2] ff ee [2] b8 ff [2] f6 f3 [2] fa f9 [2] ed f2 [2] f6 bc [2] cb }

  condition:
    any of them
}