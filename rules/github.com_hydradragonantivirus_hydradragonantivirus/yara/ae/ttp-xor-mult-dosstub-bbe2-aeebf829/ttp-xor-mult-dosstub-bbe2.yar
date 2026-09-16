rule TTP_XOR_MULT_DOSStub_bbe2 {
  strings:
    $key_bbe2 = { ef 8a [2] 9b 92 [2] dc 90 [2] 9b 81 [2] d5 8d [2] d9 87 [2] ce 8c [2] d5 c2 [2] e8 }

  condition:
    any of them
}