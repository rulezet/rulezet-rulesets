rule TTP_XOR_MULT_DOSStub_d015 {
  strings:
    $key_d015 = { 84 7d [2] f0 65 [2] b7 67 [2] f0 76 [2] be 7a [2] b2 70 [2] a5 7b [2] be 35 [2] 83 }

  condition:
    any of them
}