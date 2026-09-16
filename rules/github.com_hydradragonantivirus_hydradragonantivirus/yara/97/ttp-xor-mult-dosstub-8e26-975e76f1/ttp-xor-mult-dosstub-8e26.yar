rule TTP_XOR_MULT_DOSStub_8e26 {
  strings:
    $key_8e26 = { da 4e [2] ae 56 [2] e9 54 [2] ae 45 [2] e0 49 [2] ec 43 [2] fb 48 [2] e0 06 [2] dd }

  condition:
    any of them
}