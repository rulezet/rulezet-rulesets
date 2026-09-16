rule TTP_XOR_MULT_DOSStub_d02c {
  strings:
    $key_d02c = { 84 44 [2] f0 5c [2] b7 5e [2] f0 4f [2] be 43 [2] b2 49 [2] a5 42 [2] be 0c [2] 83 }

  condition:
    any of them
}