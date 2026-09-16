rule TTP_XOR_MULT_DOSStub_8206 {
  strings:
    $key_8206 = { d6 6e [2] a2 76 [2] e5 74 [2] a2 65 [2] ec 69 [2] e0 63 [2] f7 68 [2] ec 26 [2] d1 }

  condition:
    any of them
}