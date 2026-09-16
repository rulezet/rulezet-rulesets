rule TTP_XOR_MULT_DOSStub_162f {
  strings:
    $key_162f = { 42 47 [2] 36 5f [2] 71 5d [2] 36 4c [2] 78 40 [2] 74 4a [2] 63 41 [2] 78 0f [2] 45 }

  condition:
    any of them
}