rule TTP_XOR_MULT_DOSStub_930b {
  strings:
    $key_930b = { c7 63 [2] b3 7b [2] f4 79 [2] b3 68 [2] fd 64 [2] f1 6e [2] e6 65 [2] fd 2b [2] c0 }

  condition:
    any of them
}