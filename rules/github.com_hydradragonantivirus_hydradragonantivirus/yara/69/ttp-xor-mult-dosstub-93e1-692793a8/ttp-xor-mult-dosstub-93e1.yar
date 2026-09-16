rule TTP_XOR_MULT_DOSStub_93e1 {
  strings:
    $key_93e1 = { c7 89 [2] b3 91 [2] f4 93 [2] b3 82 [2] fd 8e [2] f1 84 [2] e6 8f [2] fd c1 [2] c0 }

  condition:
    any of them
}