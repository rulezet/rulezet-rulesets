rule TTP_XOR_MULT_DOSStub_8e2c {
  strings:
    $key_8e2c = { da 44 [2] ae 5c [2] e9 5e [2] ae 4f [2] e0 43 [2] ec 49 [2] fb 42 [2] e0 0c [2] dd }

  condition:
    any of them
}