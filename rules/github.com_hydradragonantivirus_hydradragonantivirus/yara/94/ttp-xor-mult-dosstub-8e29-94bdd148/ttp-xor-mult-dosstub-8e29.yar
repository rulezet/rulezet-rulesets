rule TTP_XOR_MULT_DOSStub_8e29 {
  strings:
    $key_8e29 = { da 41 [2] ae 59 [2] e9 5b [2] ae 4a [2] e0 46 [2] ec 4c [2] fb 47 [2] e0 09 [2] dd }

  condition:
    any of them
}