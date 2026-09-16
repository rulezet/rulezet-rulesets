rule TTP_XOR_MULT_DOSStub_063f {
  strings:
    $key_063f = { 52 57 [2] 26 4f [2] 61 4d [2] 26 5c [2] 68 50 [2] 64 5a [2] 73 51 [2] 68 1f [2] 55 }

  condition:
    any of them
}