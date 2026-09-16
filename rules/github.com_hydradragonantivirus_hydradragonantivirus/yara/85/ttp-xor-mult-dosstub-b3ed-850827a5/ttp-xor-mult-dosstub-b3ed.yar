rule TTP_XOR_MULT_DOSStub_b3ed {
  strings:
    $key_b3ed = { e7 85 [2] 93 9d [2] d4 9f [2] 93 8e [2] dd 82 [2] d1 88 [2] c6 83 [2] dd cd [2] e0 }

  condition:
    any of them
}