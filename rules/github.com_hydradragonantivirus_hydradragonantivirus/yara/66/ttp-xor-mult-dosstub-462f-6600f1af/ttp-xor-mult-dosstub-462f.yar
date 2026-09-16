rule TTP_XOR_MULT_DOSStub_462f {
  strings:
    $key_462f = { 12 47 [2] 66 5f [2] 21 5d [2] 66 4c [2] 28 40 [2] 24 4a [2] 33 41 [2] 28 0f [2] 15 }

  condition:
    any of them
}