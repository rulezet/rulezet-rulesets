rule TTP_XOR_MULT_DOSStub_8e33 {
  strings:
    $key_8e33 = { da 5b [2] ae 43 [2] e9 41 [2] ae 50 [2] e0 5c [2] ec 56 [2] fb 5d [2] e0 13 [2] dd }

  condition:
    any of them
}