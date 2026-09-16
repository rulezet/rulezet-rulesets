rule TTP_XOR_MULT_DOSStub_b778 {
  strings:
    $key_b778 = { e3 10 [2] 97 08 [2] d0 0a [2] 97 1b [2] d9 17 [2] d5 1d [2] c2 16 [2] d9 58 [2] e4 }

  condition:
    any of them
}