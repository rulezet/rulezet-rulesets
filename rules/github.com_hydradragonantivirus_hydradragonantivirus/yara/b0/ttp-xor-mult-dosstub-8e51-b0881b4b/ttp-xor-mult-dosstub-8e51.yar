rule TTP_XOR_MULT_DOSStub_8e51 {
  strings:
    $key_8e51 = { da 39 [2] ae 21 [2] e9 23 [2] ae 32 [2] e0 3e [2] ec 34 [2] fb 3f [2] e0 71 [2] dd }

  condition:
    any of them
}