rule TTP_XOR_MULT_DOSStub_3a2f {
  strings:
    $key_3a2f = { 6e 47 [2] 1a 5f [2] 5d 5d [2] 1a 4c [2] 54 40 [2] 58 4a [2] 4f 41 [2] 54 0f [2] 69 }

  condition:
    any of them
}