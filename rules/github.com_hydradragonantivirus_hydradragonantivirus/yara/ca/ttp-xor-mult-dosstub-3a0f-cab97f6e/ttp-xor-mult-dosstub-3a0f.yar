rule TTP_XOR_MULT_DOSStub_3a0f {
  strings:
    $key_3a0f = { 6e 67 [2] 1a 7f [2] 5d 7d [2] 1a 6c [2] 54 60 [2] 58 6a [2] 4f 61 [2] 54 2f [2] 69 }

  condition:
    any of them
}