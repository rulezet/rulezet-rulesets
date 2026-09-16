rule TTP_XOR_MULT_DOSStub_d02a {
  strings:
    $key_d02a = { 84 42 [2] f0 5a [2] b7 58 [2] f0 49 [2] be 45 [2] b2 4f [2] a5 44 [2] be 0a [2] 83 }

  condition:
    any of them
}