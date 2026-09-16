rule TTP_XOR_MULT_DOSStub_e6ec {
  strings:
    $key_e6ec = { b2 84 [2] c6 9c [2] 81 9e [2] c6 8f [2] 88 83 [2] 84 89 [2] 93 82 [2] 88 cc [2] b5 }

  condition:
    any of them
}