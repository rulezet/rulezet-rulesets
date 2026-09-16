rule TTP_XOR_MULT_DOSStub_8e61 {
  strings:
    $key_8e61 = { da 09 [2] ae 11 [2] e9 13 [2] ae 02 [2] e0 0e [2] ec 04 [2] fb 0f [2] e0 41 [2] dd }

  condition:
    any of them
}