rule TTP_XOR_MULT_DOSStub_c278 {
  strings:
    $key_c278 = { 96 10 [2] e2 08 [2] a5 0a [2] e2 1b [2] ac 17 [2] a0 1d [2] b7 16 [2] ac 58 [2] 91 }

  condition:
    any of them
}