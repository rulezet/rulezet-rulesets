rule TTP_XOR_MULT_DOSStub_c279 {
  strings:
    $key_c279 = { 96 11 [2] e2 09 [2] a5 0b [2] e2 1a [2] ac 16 [2] a0 1c [2] b7 17 [2] ac 59 [2] 91 }

  condition:
    any of them
}