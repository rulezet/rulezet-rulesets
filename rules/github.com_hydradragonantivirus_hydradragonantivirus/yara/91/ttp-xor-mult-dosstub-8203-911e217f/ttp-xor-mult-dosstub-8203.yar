rule TTP_XOR_MULT_DOSStub_8203 {
  strings:
    $key_8203 = { d6 6b [2] a2 73 [2] e5 71 [2] a2 60 [2] ec 6c [2] e0 66 [2] f7 6d [2] ec 23 [2] d1 }

  condition:
    any of them
}