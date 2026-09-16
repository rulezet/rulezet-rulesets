rule TTP_XOR_MULT_DOSStub_d72e {
  strings:
    $key_d72e = { 83 46 [2] f7 5e [2] b0 5c [2] f7 4d [2] b9 41 [2] b5 4b [2] a2 40 [2] b9 0e [2] 84 }

  condition:
    any of them
}