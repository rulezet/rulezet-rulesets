rule TTP_XOR_MULT_DOSStub_8e13 {
  strings:
    $key_8e13 = { da 7b [2] ae 63 [2] e9 61 [2] ae 70 [2] e0 7c [2] ec 76 [2] fb 7d [2] e0 33 [2] dd }

  condition:
    any of them
}