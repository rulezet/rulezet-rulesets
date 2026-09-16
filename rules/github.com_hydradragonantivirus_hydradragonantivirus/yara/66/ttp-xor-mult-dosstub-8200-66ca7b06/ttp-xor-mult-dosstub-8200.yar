rule TTP_XOR_MULT_DOSStub_8200 {
  strings:
    $key_8200 = { d6 68 [2] a2 70 [2] e5 72 [2] a2 63 [2] ec 6f [2] e0 65 [2] f7 6e [2] ec 20 [2] d1 }

  condition:
    any of them
}