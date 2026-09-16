rule TTP_XOR_MULT_DOSStub_7a2f {
  strings:
    $key_7a2f = { 2e 47 [2] 5a 5f [2] 1d 5d [2] 5a 4c [2] 14 40 [2] 18 4a [2] 0f 41 [2] 14 0f [2] 29 }

  condition:
    any of them
}