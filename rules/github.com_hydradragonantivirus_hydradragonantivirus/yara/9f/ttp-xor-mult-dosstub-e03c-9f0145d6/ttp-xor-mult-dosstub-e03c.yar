rule TTP_XOR_MULT_DOSStub_e03c {
  strings:
    $key_e03c = { b4 54 [2] c0 4c [2] 87 4e [2] c0 5f [2] 8e 53 [2] 82 59 [2] 95 52 [2] 8e 1c [2] b3 }

  condition:
    any of them
}