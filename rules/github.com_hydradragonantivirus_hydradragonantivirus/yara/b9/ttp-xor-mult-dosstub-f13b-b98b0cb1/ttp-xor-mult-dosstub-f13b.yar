rule TTP_XOR_MULT_DOSStub_f13b {
  strings:
    $key_f13b = { a5 53 [2] d1 4b [2] 96 49 [2] d1 58 [2] 9f 54 [2] 93 5e [2] 84 55 [2] 9f 1b [2] a2 }

  condition:
    any of them
}