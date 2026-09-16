rule TTP_XOR_MULT_DOSStub_c213 {
  strings:
    $key_c213 = { 96 7b [2] e2 63 [2] a5 61 [2] e2 70 [2] ac 7c [2] a0 76 [2] b7 7d [2] ac 33 [2] 91 }

  condition:
    any of them
}