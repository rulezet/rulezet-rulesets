rule TTP_XOR_MULT_DOSStub_c274 {
  strings:
    $key_c274 = { 96 1c [2] e2 04 [2] a5 06 [2] e2 17 [2] ac 1b [2] a0 11 [2] b7 1a [2] ac 54 [2] 91 }

  condition:
    any of them
}