rule TTP_XOR_MULT_DOSStub_e43a {
  strings:
    $key_e43a = { b0 52 [2] c4 4a [2] 83 48 [2] c4 59 [2] 8a 55 [2] 86 5f [2] 91 54 [2] 8a 1a [2] b7 }

  condition:
    any of them
}