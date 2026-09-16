rule TTP_XOR_MULT_DOSStub_c204 {
  strings:
    $key_c204 = { 96 6c [2] e2 74 [2] a5 76 [2] e2 67 [2] ac 6b [2] a0 61 [2] b7 6a [2] ac 24 [2] 91 }

  condition:
    any of them
}