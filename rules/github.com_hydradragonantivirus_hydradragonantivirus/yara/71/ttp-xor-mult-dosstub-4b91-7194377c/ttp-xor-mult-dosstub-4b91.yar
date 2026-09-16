rule TTP_XOR_MULT_DOSStub_4b91 {
  strings:
    $key_4b91 = { 1f f9 [2] 6b e1 [2] 2c e3 [2] 6b f2 [2] 25 fe [2] 29 f4 [2] 3e ff [2] 25 b1 [2] 18 }

  condition:
    any of them
}