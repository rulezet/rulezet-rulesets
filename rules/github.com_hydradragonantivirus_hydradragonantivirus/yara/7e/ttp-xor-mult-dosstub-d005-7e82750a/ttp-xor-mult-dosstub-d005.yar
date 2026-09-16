rule TTP_XOR_MULT_DOSStub_d005 {
  strings:
    $key_d005 = { 84 6d [2] f0 75 [2] b7 77 [2] f0 66 [2] be 6a [2] b2 60 [2] a5 6b [2] be 25 [2] 83 }

  condition:
    any of them
}