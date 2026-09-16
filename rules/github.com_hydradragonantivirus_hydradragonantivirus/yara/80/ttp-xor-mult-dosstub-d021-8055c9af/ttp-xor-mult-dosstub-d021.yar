rule TTP_XOR_MULT_DOSStub_d021 {
  strings:
    $key_d021 = { 84 49 [2] f0 51 [2] b7 53 [2] f0 42 [2] be 4e [2] b2 44 [2] a5 4f [2] be 01 [2] 83 }

  condition:
    any of them
}