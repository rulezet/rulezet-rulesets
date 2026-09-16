rule TTP_XOR_MULT_DOSStub_d72b {
  strings:
    $key_d72b = { 83 43 [2] f7 5b [2] b0 59 [2] f7 48 [2] b9 44 [2] b5 4e [2] a2 45 [2] b9 0b [2] 84 }

  condition:
    any of them
}