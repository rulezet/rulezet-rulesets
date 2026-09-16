rule TTP_XOR_MULT_DOSStub_e272 {
  strings:
    $key_e272 = { b6 1a [2] c2 02 [2] 85 00 [2] c2 11 [2] 8c 1d [2] 80 17 [2] 97 1c [2] 8c 52 [2] b1 }

  condition:
    any of them
}