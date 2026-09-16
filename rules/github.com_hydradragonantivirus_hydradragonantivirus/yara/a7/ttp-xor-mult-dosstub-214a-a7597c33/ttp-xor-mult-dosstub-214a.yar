rule TTP_XOR_MULT_DOSStub_214a {
  strings:
    $key_214a = { 75 22 [2] 01 3a [2] 46 38 [2] 01 29 [2] 4f 25 [2] 43 2f [2] 54 24 [2] 4f 6a [2] 72 }

  condition:
    any of them
}