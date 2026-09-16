rule TTP_XOR_MULT_DOSStub_e17a {
  strings:
    $key_e17a = { b5 12 [2] c1 0a [2] 86 08 [2] c1 19 [2] 8f 15 [2] 83 1f [2] 94 14 [2] 8f 5a [2] b2 }

  condition:
    any of them
}