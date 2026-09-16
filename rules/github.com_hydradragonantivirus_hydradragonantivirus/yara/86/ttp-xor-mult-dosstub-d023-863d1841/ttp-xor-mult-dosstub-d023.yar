rule TTP_XOR_MULT_DOSStub_d023 {
  strings:
    $key_d023 = { 84 4b [2] f0 53 [2] b7 51 [2] f0 40 [2] be 4c [2] b2 46 [2] a5 4d [2] be 03 [2] 83 }

  condition:
    any of them
}