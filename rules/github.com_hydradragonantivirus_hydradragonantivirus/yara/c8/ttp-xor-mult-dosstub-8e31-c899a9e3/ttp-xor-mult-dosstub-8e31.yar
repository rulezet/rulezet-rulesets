rule TTP_XOR_MULT_DOSStub_8e31 {
  strings:
    $key_8e31 = { da 59 [2] ae 41 [2] e9 43 [2] ae 52 [2] e0 5e [2] ec 54 [2] fb 5f [2] e0 11 [2] dd }

  condition:
    any of them
}