rule TTP_XOR_MULT_DOSStub_c218 {
  strings:
    $key_c218 = { 96 70 [2] e2 68 [2] a5 6a [2] e2 7b [2] ac 77 [2] a0 7d [2] b7 76 [2] ac 38 [2] 91 }

  condition:
    any of them
}