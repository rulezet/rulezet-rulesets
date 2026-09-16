rule TTP_XOR_MULT_DOSStub_e53a {
  strings:
    $key_e53a = { b1 52 [2] c5 4a [2] 82 48 [2] c5 59 [2] 8b 55 [2] 87 5f [2] 90 54 [2] 8b 1a [2] b6 }

  condition:
    any of them
}