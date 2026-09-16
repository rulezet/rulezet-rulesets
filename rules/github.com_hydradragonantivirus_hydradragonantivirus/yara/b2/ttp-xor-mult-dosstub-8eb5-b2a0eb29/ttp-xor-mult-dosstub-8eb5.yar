rule TTP_XOR_MULT_DOSStub_8eb5 {
  strings:
    $key_8eb5 = { da dd [2] ae c5 [2] e9 c7 [2] ae d6 [2] e0 da [2] ec d0 [2] fb db [2] e0 95 [2] dd }

  condition:
    any of them
}