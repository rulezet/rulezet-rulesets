rule TTP_XOR_MULT_DOSStub_8ef0 {
  strings:
    $key_8ef0 = { da 98 [2] ae 80 [2] e9 82 [2] ae 93 [2] e0 9f [2] ec 95 [2] fb 9e [2] e0 d0 [2] dd }

  condition:
    any of them
}