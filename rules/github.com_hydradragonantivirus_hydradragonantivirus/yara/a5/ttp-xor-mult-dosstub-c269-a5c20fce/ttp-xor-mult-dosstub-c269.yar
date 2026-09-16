rule TTP_XOR_MULT_DOSStub_c269 {
  strings:
    $key_c269 = { 96 01 [2] e2 19 [2] a5 1b [2] e2 0a [2] ac 06 [2] a0 0c [2] b7 07 [2] ac 49 [2] 91 }

  condition:
    any of them
}