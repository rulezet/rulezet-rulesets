rule TTP_XOR_MULT_DOSStub_820b {
  strings:
    $key_820b = { d6 63 [2] a2 7b [2] e5 79 [2] a2 68 [2] ec 64 [2] e0 6e [2] f7 65 [2] ec 2b [2] d1 }

  condition:
    any of them
}