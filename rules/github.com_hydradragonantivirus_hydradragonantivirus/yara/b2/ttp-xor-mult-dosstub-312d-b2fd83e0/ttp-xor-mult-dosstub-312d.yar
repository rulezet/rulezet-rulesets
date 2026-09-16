rule TTP_XOR_MULT_DOSStub_312d {
  strings:
    $key_312d = { 65 45 [2] 11 5d [2] 56 5f [2] 11 4e [2] 5f 42 [2] 53 48 [2] 44 43 [2] 5f 0d [2] 62 }

  condition:
    any of them
}