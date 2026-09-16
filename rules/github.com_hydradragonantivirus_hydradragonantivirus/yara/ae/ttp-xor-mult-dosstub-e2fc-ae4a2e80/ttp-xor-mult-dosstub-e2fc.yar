rule TTP_XOR_MULT_DOSStub_e2fc {
  strings:
    $key_e2fc = { b6 94 [2] c2 8c [2] 85 8e [2] c2 9f [2] 8c 93 [2] 80 99 [2] 97 92 [2] 8c dc [2] b1 }

  condition:
    any of them
}