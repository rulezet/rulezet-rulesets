rule TTP_XOR_MULT_DOSStub_317f {
  strings:
    $key_317f = { 65 17 [2] 11 0f [2] 56 0d [2] 11 1c [2] 5f 10 [2] 53 1a [2] 44 11 [2] 5f 5f [2] 62 }

  condition:
    any of them
}