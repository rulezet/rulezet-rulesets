rule TTP_XOR_MULT_DOSStub_faf3 {
  strings:
    $key_faf3 = { ae 9b [2] da 83 [2] 9d 81 [2] da 90 [2] 94 9c [2] 98 96 [2] 8f 9d [2] 94 d3 [2] a9 }

  condition:
    any of them
}