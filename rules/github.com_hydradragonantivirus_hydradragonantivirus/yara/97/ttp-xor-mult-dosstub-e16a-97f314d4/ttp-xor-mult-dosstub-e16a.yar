rule TTP_XOR_MULT_DOSStub_e16a {
  strings:
    $key_e16a = { b5 02 [2] c1 1a [2] 86 18 [2] c1 09 [2] 8f 05 [2] 83 0f [2] 94 04 [2] 8f 4a [2] b2 }

  condition:
    any of them
}