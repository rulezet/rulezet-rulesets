rule TTP_XOR_MULT_DOSStub_8e20 {
  strings:
    $key_8e20 = { da 48 [2] ae 50 [2] e9 52 [2] ae 43 [2] e0 4f [2] ec 45 [2] fb 4e [2] e0 00 [2] dd }

  condition:
    any of them
}