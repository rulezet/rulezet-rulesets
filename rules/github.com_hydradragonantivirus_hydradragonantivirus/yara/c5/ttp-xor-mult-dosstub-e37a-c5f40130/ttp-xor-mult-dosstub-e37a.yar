rule TTP_XOR_MULT_DOSStub_e37a {
  strings:
    $key_e37a = { b7 12 [2] c3 0a [2] 84 08 [2] c3 19 [2] 8d 15 [2] 81 1f [2] 96 14 [2] 8d 5a [2] b0 }

  condition:
    any of them
}