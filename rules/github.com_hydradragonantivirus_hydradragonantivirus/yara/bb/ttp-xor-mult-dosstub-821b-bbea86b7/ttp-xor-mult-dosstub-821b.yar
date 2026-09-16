rule TTP_XOR_MULT_DOSStub_821b {
  strings:
    $key_821b = { d6 73 [2] a2 6b [2] e5 69 [2] a2 78 [2] ec 74 [2] e0 7e [2] f7 75 [2] ec 3b [2] d1 }

  condition:
    any of them
}