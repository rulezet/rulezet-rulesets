rule TTP_XOR_MULT_DOSStub_d63a {
  strings:
    $key_d63a = { 82 52 [2] f6 4a [2] b1 48 [2] f6 59 [2] b8 55 [2] b4 5f [2] a3 54 [2] b8 1a [2] 85 }

  condition:
    any of them
}