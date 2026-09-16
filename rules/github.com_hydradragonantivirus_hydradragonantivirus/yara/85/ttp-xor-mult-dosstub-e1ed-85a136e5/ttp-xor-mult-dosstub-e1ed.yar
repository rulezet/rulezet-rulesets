rule TTP_XOR_MULT_DOSStub_e1ed {
  strings:
    $key_e1ed = { b5 85 [2] c1 9d [2] 86 9f [2] c1 8e [2] 8f 82 [2] 83 88 [2] 94 83 [2] 8f cd [2] b2 }

  condition:
    any of them
}