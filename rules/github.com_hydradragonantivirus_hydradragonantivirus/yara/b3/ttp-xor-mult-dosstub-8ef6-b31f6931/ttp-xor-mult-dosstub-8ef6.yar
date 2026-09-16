rule TTP_XOR_MULT_DOSStub_8ef6 {
  strings:
    $key_8ef6 = { da 9e [2] ae 86 [2] e9 84 [2] ae 95 [2] e0 99 [2] ec 93 [2] fb 98 [2] e0 d6 [2] dd }

  condition:
    any of them
}