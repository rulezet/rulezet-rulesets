rule TTP_XOR_MULT_DOSStub_82f5 {
  strings:
    $key_82f5 = { d6 9d [2] a2 85 [2] e5 87 [2] a2 96 [2] ec 9a [2] e0 90 [2] f7 9b [2] ec d5 [2] d1 }

  condition:
    any of them
}