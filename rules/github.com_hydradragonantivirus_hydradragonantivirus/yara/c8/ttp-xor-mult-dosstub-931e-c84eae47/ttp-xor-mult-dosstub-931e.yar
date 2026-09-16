rule TTP_XOR_MULT_DOSStub_931e {
  strings:
    $key_931e = { c7 76 [2] b3 6e [2] f4 6c [2] b3 7d [2] fd 71 [2] f1 7b [2] e6 70 [2] fd 3e [2] c0 }

  condition:
    any of them
}