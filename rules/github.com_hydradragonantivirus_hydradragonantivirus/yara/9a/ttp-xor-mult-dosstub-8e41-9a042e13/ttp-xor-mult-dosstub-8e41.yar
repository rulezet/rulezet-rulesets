rule TTP_XOR_MULT_DOSStub_8e41 {
  strings:
    $key_8e41 = { da 29 [2] ae 31 [2] e9 33 [2] ae 22 [2] e0 2e [2] ec 24 [2] fb 2f [2] e0 61 [2] dd }

  condition:
    any of them
}