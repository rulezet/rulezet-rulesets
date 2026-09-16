rule TTP_XOR_MULT_DOSStub_3b91 {
  strings:
    $key_3b91 = { 6f f9 [2] 1b e1 [2] 5c e3 [2] 1b f2 [2] 55 fe [2] 59 f4 [2] 4e ff [2] 55 b1 [2] 68 }

  condition:
    any of them
}