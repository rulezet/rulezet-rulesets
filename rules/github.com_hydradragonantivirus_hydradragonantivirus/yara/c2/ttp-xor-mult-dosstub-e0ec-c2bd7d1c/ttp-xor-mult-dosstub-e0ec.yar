rule TTP_XOR_MULT_DOSStub_e0ec {
  strings:
    $key_e0ec = { b4 84 [2] c0 9c [2] 87 9e [2] c0 8f [2] 8e 83 [2] 82 89 [2] 95 82 [2] 8e cc [2] b3 }

  condition:
    any of them
}