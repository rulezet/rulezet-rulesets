rule TTP_XOR_MULT_DOSStub_f16a {
  strings:
    $key_f16a = { a5 02 [2] d1 1a [2] 96 18 [2] d1 09 [2] 9f 05 [2] 93 0f [2] 84 04 [2] 9f 4a [2] a2 }

  condition:
    any of them
}