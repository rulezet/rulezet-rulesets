rule TTP_XOR_MULT_DOSStub_e76a {
  strings:
    $key_e76a = { b3 02 [2] c7 1a [2] 80 18 [2] c7 09 [2] 89 05 [2] 85 0f [2] 92 04 [2] 89 4a [2] b4 }

  condition:
    any of them
}