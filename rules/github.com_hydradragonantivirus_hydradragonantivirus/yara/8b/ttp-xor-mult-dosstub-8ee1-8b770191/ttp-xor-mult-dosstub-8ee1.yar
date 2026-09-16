rule TTP_XOR_MULT_DOSStub_8ee1 {
  strings:
    $key_8ee1 = { da 89 [2] ae 91 [2] e9 93 [2] ae 82 [2] e0 8e [2] ec 84 [2] fb 8f [2] e0 c1 [2] dd }

  condition:
    any of them
}