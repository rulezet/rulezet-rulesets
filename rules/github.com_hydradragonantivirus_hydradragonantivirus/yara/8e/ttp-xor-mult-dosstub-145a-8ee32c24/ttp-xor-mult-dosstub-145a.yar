rule TTP_XOR_MULT_DOSStub_145a {
  strings:
    $key_145a = { 40 32 [2] 34 2a [2] 73 28 [2] 34 39 [2] 7a 35 [2] 76 3f [2] 61 34 [2] 7a 7a [2] 47 }

  condition:
    any of them
}