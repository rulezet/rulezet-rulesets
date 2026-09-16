rule TTP_XOR_MULT_DOSStub_d77c {
  strings:
    $key_d77c = { 83 14 [2] f7 0c [2] b0 0e [2] f7 1f [2] b9 13 [2] b5 19 [2] a2 12 [2] b9 5c [2] 84 }

  condition:
    any of them
}