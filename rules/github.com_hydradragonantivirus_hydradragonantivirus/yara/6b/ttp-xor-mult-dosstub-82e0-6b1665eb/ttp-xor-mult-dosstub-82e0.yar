rule TTP_XOR_MULT_DOSStub_82e0 {
  strings:
    $key_82e0 = { d6 88 [2] a2 90 [2] e5 92 [2] a2 83 [2] ec 8f [2] e0 85 [2] f7 8e [2] ec c0 [2] d1 }

  condition:
    any of them
}