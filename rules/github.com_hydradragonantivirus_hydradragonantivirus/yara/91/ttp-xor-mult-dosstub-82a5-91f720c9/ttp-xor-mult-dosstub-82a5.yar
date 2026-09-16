rule TTP_XOR_MULT_DOSStub_82a5 {
  strings:
    $key_82a5 = { d6 cd [2] a2 d5 [2] e5 d7 [2] a2 c6 [2] ec ca [2] e0 c0 [2] f7 cb [2] ec 85 [2] d1 }

  condition:
    any of them
}