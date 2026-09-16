rule TTP_XOR_MULT_DOSStub_f147 {
  strings:
    $key_f147 = { a5 2f [2] d1 37 [2] 96 35 [2] d1 24 [2] 9f 28 [2] 93 22 [2] 84 29 [2] 9f 67 [2] a2 }

  condition:
    any of them
}