rule TTP_XOR_MULT_DOSStub_8e21 {
  strings:
    $key_8e21 = { da 49 [2] ae 51 [2] e9 53 [2] ae 42 [2] e0 4e [2] ec 44 [2] fb 4f [2] e0 01 [2] dd }

  condition:
    any of them
}