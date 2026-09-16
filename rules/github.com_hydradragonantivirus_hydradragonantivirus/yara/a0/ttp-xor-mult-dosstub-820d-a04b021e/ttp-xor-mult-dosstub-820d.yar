rule TTP_XOR_MULT_DOSStub_820d {
  strings:
    $key_820d = { d6 65 [2] a2 7d [2] e5 7f [2] a2 6e [2] ec 62 [2] e0 68 [2] f7 63 [2] ec 2d [2] d1 }

  condition:
    any of them
}