rule TTP_XOR_MULT_DOSStub_c202 {
  strings:
    $key_c202 = { 96 6a [2] e2 72 [2] a5 70 [2] e2 61 [2] ac 6d [2] a0 67 [2] b7 6c [2] ac 22 [2] 91 }

  condition:
    any of them
}