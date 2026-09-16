rule TTP_XOR_MULT_DOSStub_c3ea {
  strings:
    $key_c3ea = { 97 82 [2] e3 9a [2] a4 98 [2] e3 89 [2] ad 85 [2] a1 8f [2] b6 84 [2] ad ca [2] 90 }

  condition:
    any of them
}