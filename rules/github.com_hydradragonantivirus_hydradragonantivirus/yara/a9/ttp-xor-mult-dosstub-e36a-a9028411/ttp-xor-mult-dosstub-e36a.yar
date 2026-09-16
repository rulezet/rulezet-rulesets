rule TTP_XOR_MULT_DOSStub_e36a {
  strings:
    $key_e36a = { b7 02 [2] c3 1a [2] 84 18 [2] c3 09 [2] 8d 05 [2] 81 0f [2] 96 04 [2] 8d 4a [2] b0 }

  condition:
    any of them
}