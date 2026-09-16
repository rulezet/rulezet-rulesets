rule TTP_XOR_MULT_DOSStub_84a5 {
  strings:
    $key_84a5 = { d0 cd [2] a4 d5 [2] e3 d7 [2] a4 c6 [2] ea ca [2] e6 c0 [2] f1 cb [2] ea 85 [2] d7 }

  condition:
    any of them
}