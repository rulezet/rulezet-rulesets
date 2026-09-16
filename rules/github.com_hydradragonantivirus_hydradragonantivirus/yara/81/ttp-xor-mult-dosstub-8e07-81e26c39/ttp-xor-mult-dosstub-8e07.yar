rule TTP_XOR_MULT_DOSStub_8e07 {
  strings:
    $key_8e07 = { da 6f [2] ae 77 [2] e9 75 [2] ae 64 [2] e0 68 [2] ec 62 [2] fb 69 [2] e0 27 [2] dd }

  condition:
    any of them
}