rule TTP_XOR_MULT_DOSStub_828d {
  strings:
    $key_828d = { d6 e5 [2] a2 fd [2] e5 ff [2] a2 ee [2] ec e2 [2] e0 e8 [2] f7 e3 [2] ec ad [2] d1 }

  condition:
    any of them
}