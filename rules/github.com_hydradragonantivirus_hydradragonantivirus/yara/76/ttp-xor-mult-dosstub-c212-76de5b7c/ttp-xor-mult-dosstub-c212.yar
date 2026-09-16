rule TTP_XOR_MULT_DOSStub_c212 {
  strings:
    $key_c212 = { 96 7a [2] e2 62 [2] a5 60 [2] e2 71 [2] ac 7d [2] a0 77 [2] b7 7c [2] ac 32 [2] 91 }

  condition:
    any of them
}