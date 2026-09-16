rule TTP_XOR_MULT_DOSStub_8e18 {
  strings:
    $key_8e18 = { da 70 [2] ae 68 [2] e9 6a [2] ae 7b [2] e0 77 [2] ec 7d [2] fb 76 [2] e0 38 [2] dd }

  condition:
    any of them
}