rule TTP_XOR_MULT_DOSStub_93ac {
  strings:
    $key_93ac = { c7 c4 [2] b3 dc [2] f4 de [2] b3 cf [2] fd c3 [2] f1 c9 [2] e6 c2 [2] fd 8c [2] c0 }

  condition:
    any of them
}