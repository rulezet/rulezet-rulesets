rule TTP_XOR_MULT_DOSStub_8e93 {
  strings:
    $key_8e93 = { da fb [2] ae e3 [2] e9 e1 [2] ae f0 [2] e0 fc [2] ec f6 [2] fb fd [2] e0 b3 [2] dd }

  condition:
    any of them
}