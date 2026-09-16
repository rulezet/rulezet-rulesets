rule TTP_XOR_MULT_DOSStub_c522 {
  strings:
    $key_c522 = { 91 4a [2] e5 52 [2] a2 50 [2] e5 41 [2] ab 4d [2] a7 47 [2] b0 4c [2] ab 02 [2] 96 }

  condition:
    any of them
}