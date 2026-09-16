rule TTP_XOR_MULT_DOSStub_949c {
  strings:
    $key_949c = { c0 f4 [2] b4 ec [2] f3 ee [2] b4 ff [2] fa f3 [2] f6 f9 [2] e1 f2 [2] fa bc [2] c7 }

  condition:
    any of them
}