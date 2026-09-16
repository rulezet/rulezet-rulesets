rule TTP_XOR_MULT_DOSStub_8ee2 {
  strings:
    $key_8ee2 = { da 8a [2] ae 92 [2] e9 90 [2] ae 81 [2] e0 8d [2] ec 87 [2] fb 8c [2] e0 c2 [2] dd }

  condition:
    any of them
}