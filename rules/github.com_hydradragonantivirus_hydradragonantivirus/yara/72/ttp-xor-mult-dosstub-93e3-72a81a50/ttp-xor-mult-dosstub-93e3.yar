rule TTP_XOR_MULT_DOSStub_93e3 {
  strings:
    $key_93e3 = { c7 8b [2] b3 93 [2] f4 91 [2] b3 80 [2] fd 8c [2] f1 86 [2] e6 8d [2] fd c3 [2] c0 }

  condition:
    any of them
}