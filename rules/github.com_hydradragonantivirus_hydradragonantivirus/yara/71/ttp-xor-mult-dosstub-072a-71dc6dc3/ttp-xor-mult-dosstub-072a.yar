rule TTP_XOR_MULT_DOSStub_072a {
  strings:
    $key_072a = { 53 42 [2] 27 5a [2] 60 58 [2] 27 49 [2] 69 45 [2] 65 4f [2] 72 44 [2] 69 0a [2] 54 }

  condition:
    any of them
}