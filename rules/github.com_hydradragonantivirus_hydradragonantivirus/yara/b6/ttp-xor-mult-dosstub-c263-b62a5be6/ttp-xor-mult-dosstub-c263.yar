rule TTP_XOR_MULT_DOSStub_c263 {
  strings:
    $key_c263 = { 96 0b [2] e2 13 [2] a5 11 [2] e2 00 [2] ac 0c [2] a0 06 [2] b7 0d [2] ac 43 [2] 91 }

  condition:
    any of them
}