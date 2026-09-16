rule TTP_XOR_MULT_DOSStub_8e67 {
  strings:
    $key_8e67 = { da 0f [2] ae 17 [2] e9 15 [2] ae 04 [2] e0 08 [2] ec 02 [2] fb 09 [2] e0 47 [2] dd }

  condition:
    any of them
}