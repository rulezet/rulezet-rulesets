rule TTP_XOR_MULT_DOSStub_8237 {
  strings:
    $key_8237 = { d6 5f [2] a2 47 [2] e5 45 [2] a2 54 [2] ec 58 [2] e0 52 [2] f7 59 [2] ec 17 [2] d1 }

  condition:
    any of them
}