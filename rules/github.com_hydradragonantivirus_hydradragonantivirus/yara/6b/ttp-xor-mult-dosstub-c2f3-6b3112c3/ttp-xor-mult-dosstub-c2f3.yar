rule TTP_XOR_MULT_DOSStub_c2f3 {
  strings:
    $key_c2f3 = { 96 9b [2] e2 83 [2] a5 81 [2] e2 90 [2] ac 9c [2] a0 96 [2] b7 9d [2] ac d3 [2] 91 }

  condition:
    any of them
}