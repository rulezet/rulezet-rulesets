rule TTP_XOR_MULT_DOSStub_b1fc {
  strings:
    $key_b1fc = { e5 94 [2] 91 8c [2] d6 8e [2] 91 9f [2] df 93 [2] d3 99 [2] c4 92 [2] df dc [2] e2 }

  condition:
    any of them
}