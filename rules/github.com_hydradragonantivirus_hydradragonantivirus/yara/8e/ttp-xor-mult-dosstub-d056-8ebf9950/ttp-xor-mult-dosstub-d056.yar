rule TTP_XOR_MULT_DOSStub_d056 {
  strings:
    $key_d056 = { 84 3e [2] f0 26 [2] b7 24 [2] f0 35 [2] be 39 [2] b2 33 [2] a5 38 [2] be 76 [2] 83 }

  condition:
    any of them
}