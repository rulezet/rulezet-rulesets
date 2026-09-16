rule TTP_XOR_MULT_DOSStub_e26a {
  strings:
    $key_e26a = { b6 02 [2] c2 1a [2] 85 18 [2] c2 09 [2] 8c 05 [2] 80 0f [2] 97 04 [2] 8c 4a [2] b1 }

  condition:
    any of them
}