rule TTP_XOR_MULT_DOSStub_b70c {
  strings:
    $key_b70c = { e3 64 [2] 97 7c [2] d0 7e [2] 97 6f [2] d9 63 [2] d5 69 [2] c2 62 [2] d9 2c [2] e4 }

  condition:
    any of them
}