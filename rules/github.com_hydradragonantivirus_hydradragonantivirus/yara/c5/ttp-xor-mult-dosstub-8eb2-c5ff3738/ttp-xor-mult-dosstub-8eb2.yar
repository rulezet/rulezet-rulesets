rule TTP_XOR_MULT_DOSStub_8eb2 {
  strings:
    $key_8eb2 = { da da [2] ae c2 [2] e9 c0 [2] ae d1 [2] e0 dd [2] ec d7 [2] fb dc [2] e0 92 [2] dd }

  condition:
    any of them
}