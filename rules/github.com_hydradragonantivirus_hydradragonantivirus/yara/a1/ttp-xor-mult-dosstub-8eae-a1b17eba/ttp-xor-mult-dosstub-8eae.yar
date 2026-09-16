rule TTP_XOR_MULT_DOSStub_8eae {
  strings:
    $key_8eae = { da c6 [2] ae de [2] e9 dc [2] ae cd [2] e0 c1 [2] ec cb [2] fb c0 [2] e0 8e [2] dd }

  condition:
    any of them
}