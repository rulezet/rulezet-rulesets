rule TTP_XOR_MULT_DOSStub_8e37 {
  strings:
    $key_8e37 = { da 5f [2] ae 47 [2] e9 45 [2] ae 54 [2] e0 58 [2] ec 52 [2] fb 59 [2] e0 17 [2] dd }

  condition:
    any of them
}