rule TTP_XOR_MULT_DOSStub_82a3 {
  strings:
    $key_82a3 = { d6 cb [2] a2 d3 [2] e5 d1 [2] a2 c0 [2] ec cc [2] e0 c6 [2] f7 cd [2] ec 83 [2] d1 }

  condition:
    any of them
}