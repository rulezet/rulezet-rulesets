rule TTP_XOR_MULT_DOSStub_e12c {
  strings:
    $key_e12c = { b5 44 [2] c1 5c [2] 86 5e [2] c1 4f [2] 8f 43 [2] 83 49 [2] 94 42 [2] 8f 0c [2] b2 }

  condition:
    any of them
}