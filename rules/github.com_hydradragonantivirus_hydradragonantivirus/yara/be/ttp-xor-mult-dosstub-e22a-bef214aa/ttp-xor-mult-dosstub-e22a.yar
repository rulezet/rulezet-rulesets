rule TTP_XOR_MULT_DOSStub_e22a {
  strings:
    $key_e22a = { b6 42 [2] c2 5a [2] 85 58 [2] c2 49 [2] 8c 45 [2] 80 4f [2] 97 44 [2] 8c 0a [2] b1 }

  condition:
    any of them
}