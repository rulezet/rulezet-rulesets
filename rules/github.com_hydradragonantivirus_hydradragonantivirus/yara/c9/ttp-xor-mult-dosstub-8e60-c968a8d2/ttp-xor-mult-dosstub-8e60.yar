rule TTP_XOR_MULT_DOSStub_8e60 {
  strings:
    $key_8e60 = { da 08 [2] ae 10 [2] e9 12 [2] ae 03 [2] e0 0f [2] ec 05 [2] fb 0e [2] e0 40 [2] dd }

  condition:
    any of them
}