rule TTP_XOR_MULT_DOSStub_82af {
  strings:
    $key_82af = { d6 c7 [2] a2 df [2] e5 dd [2] a2 cc [2] ec c0 [2] e0 ca [2] f7 c1 [2] ec 8f [2] d1 }

  condition:
    any of them
}