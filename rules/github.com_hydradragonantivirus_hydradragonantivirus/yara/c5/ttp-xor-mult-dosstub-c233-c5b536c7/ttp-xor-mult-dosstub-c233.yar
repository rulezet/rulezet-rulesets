rule TTP_XOR_MULT_DOSStub_c233 {
  strings:
    $key_c233 = { 96 5b [2] e2 43 [2] a5 41 [2] e2 50 [2] ac 5c [2] a0 56 [2] b7 5d [2] ac 13 [2] 91 }

  condition:
    any of them
}