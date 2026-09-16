rule TTP_XOR_MULT_DOSStub_8e8a {
  strings:
    $key_8e8a = { da e2 [2] ae fa [2] e9 f8 [2] ae e9 [2] e0 e5 [2] ec ef [2] fb e4 [2] e0 aa [2] dd }

  condition:
    any of them
}