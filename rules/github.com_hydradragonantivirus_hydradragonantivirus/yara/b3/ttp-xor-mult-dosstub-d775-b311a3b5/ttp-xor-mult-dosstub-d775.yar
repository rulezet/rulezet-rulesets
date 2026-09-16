rule TTP_XOR_MULT_DOSStub_d775 {
  strings:
    $key_d775 = { 83 1d [2] f7 05 [2] b0 07 [2] f7 16 [2] b9 1a [2] b5 10 [2] a2 1b [2] b9 55 [2] 84 }

  condition:
    any of them
}