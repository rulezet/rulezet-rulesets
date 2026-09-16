rule TTP_XOR_MULT_DOSStub_d025 {
  strings:
    $key_d025 = { 84 4d [2] f0 55 [2] b7 57 [2] f0 46 [2] be 4a [2] b2 40 [2] a5 4b [2] be 05 [2] 83 }

  condition:
    any of them
}