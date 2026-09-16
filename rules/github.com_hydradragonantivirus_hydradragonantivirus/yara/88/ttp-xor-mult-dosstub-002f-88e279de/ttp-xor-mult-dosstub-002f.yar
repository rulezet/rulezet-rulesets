rule TTP_XOR_MULT_DOSStub_002f {
  strings:
    $key_002f = { 54 47 [2] 20 5f [2] 67 5d [2] 20 4c [2] 6e 40 [2] 62 4a [2] 75 41 [2] 6e 0f [2] 53 }

  condition:
    any of them
}