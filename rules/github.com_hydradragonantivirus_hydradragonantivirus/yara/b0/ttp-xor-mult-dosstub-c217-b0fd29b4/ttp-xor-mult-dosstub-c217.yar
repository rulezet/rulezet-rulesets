rule TTP_XOR_MULT_DOSStub_c217 {
  strings:
    $key_c217 = { 96 7f [2] e2 67 [2] a5 65 [2] e2 74 [2] ac 78 [2] a0 72 [2] b7 79 [2] ac 37 [2] 91 }

  condition:
    any of them
}