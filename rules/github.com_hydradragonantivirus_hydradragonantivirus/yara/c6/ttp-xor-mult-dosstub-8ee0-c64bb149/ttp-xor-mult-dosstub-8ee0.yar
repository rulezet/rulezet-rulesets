rule TTP_XOR_MULT_DOSStub_8ee0 {
  strings:
    $key_8ee0 = { da 88 [2] ae 90 [2] e9 92 [2] ae 83 [2] e0 8f [2] ec 85 [2] fb 8e [2] e0 c0 [2] dd }

  condition:
    any of them
}