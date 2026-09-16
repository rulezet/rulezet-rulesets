rule TTP_XOR_MULT_DOSStub_e6ea {
  strings:
    $key_e6ea = { b2 82 [2] c6 9a [2] 81 98 [2] c6 89 [2] 88 85 [2] 84 8f [2] 93 84 [2] 88 ca [2] b5 }

  condition:
    any of them
}