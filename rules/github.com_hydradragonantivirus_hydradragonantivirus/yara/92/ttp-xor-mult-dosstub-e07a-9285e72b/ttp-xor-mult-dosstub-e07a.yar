rule TTP_XOR_MULT_DOSStub_e07a {
  strings:
    $key_e07a = { b4 12 [2] c0 0a [2] 87 08 [2] c0 19 [2] 8e 15 [2] 82 1f [2] 95 14 [2] 8e 5a [2] b3 }

  condition:
    any of them
}