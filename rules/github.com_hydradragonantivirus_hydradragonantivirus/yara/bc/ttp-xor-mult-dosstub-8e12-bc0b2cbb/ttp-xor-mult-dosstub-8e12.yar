rule TTP_XOR_MULT_DOSStub_8e12 {
  strings:
    $key_8e12 = { da 7a [2] ae 62 [2] e9 60 [2] ae 71 [2] e0 7d [2] ec 77 [2] fb 7c [2] e0 32 [2] dd }

  condition:
    any of them
}