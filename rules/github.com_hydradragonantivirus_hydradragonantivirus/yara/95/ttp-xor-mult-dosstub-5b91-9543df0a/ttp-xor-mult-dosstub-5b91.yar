rule TTP_XOR_MULT_DOSStub_5b91 {
  strings:
    $key_5b91 = { 0f f9 [2] 7b e1 [2] 3c e3 [2] 7b f2 [2] 35 fe [2] 39 f4 [2] 2e ff [2] 35 b1 [2] 08 }

  condition:
    any of them
}