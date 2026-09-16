rule TTP_XOR_MULT_DOSStub_0710 {
  strings:
    $key_0710 = { 53 78 [2] 27 60 [2] 60 62 [2] 27 73 [2] 69 7f [2] 65 75 [2] 72 7e [2] 69 30 [2] 54 }

  condition:
    any of them
}