rule TTP_XOR_MULT_DOSStub_930e {
  strings:
    $key_930e = { c7 66 [2] b3 7e [2] f4 7c [2] b3 6d [2] fd 61 [2] f1 6b [2] e6 60 [2] fd 2e [2] c0 }

  condition:
    any of them
}