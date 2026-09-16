rule TTP_XOR_MULT_DOSStub_8217 {
  strings:
    $key_8217 = { d6 7f [2] a2 67 [2] e5 65 [2] a2 74 [2] ec 78 [2] e0 72 [2] f7 79 [2] ec 37 [2] d1 }

  condition:
    any of them
}