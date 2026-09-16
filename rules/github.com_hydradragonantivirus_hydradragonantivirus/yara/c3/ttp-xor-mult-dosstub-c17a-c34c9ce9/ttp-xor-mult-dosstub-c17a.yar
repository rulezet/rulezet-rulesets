rule TTP_XOR_MULT_DOSStub_c17a {
  strings:
    $key_c17a = { 95 12 [2] e1 0a [2] a6 08 [2] e1 19 [2] af 15 [2] a3 1f [2] b4 14 [2] af 5a [2] 92 }

  condition:
    any of them
}