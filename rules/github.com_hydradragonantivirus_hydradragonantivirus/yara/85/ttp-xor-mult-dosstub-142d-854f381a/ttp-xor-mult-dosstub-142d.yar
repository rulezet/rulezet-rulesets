rule TTP_XOR_MULT_DOSStub_142d {
  strings:
    $key_142d = { 40 45 [2] 34 5d [2] 73 5f [2] 34 4e [2] 7a 42 [2] 76 48 [2] 61 43 [2] 7a 0d [2] 47 }

  condition:
    any of them
}