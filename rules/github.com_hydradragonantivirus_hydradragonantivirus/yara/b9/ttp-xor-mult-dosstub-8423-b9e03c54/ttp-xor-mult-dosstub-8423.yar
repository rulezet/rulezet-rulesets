rule TTP_XOR_MULT_DOSStub_8423 {
  strings:
    $key_8423 = { d0 4b [2] a4 53 [2] e3 51 [2] a4 40 [2] ea 4c [2] e6 46 [2] f1 4d [2] ea 03 [2] d7 }

  condition:
    any of them
}