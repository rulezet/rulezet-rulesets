rule TTP_XOR_MULT_DOSStub_82fd {
  strings:
    $key_82fd = { d6 95 [2] a2 8d [2] e5 8f [2] a2 9e [2] ec 92 [2] e0 98 [2] f7 93 [2] ec dd [2] d1 }

  condition:
    any of them
}