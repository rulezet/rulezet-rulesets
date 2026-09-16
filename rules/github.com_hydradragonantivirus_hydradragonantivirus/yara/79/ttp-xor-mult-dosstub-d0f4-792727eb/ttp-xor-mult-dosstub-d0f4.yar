rule TTP_XOR_MULT_DOSStub_d0f4 {
  strings:
    $key_d0f4 = { 84 9c [2] f0 84 [2] b7 86 [2] f0 97 [2] be 9b [2] b2 91 [2] a5 9a [2] be d4 [2] 83 }

  condition:
    any of them
}