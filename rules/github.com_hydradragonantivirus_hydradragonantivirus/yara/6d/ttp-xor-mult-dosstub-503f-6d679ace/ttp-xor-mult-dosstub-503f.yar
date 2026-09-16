rule TTP_XOR_MULT_DOSStub_503f {
  strings:
    $key_503f = { 04 57 [2] 70 4f [2] 37 4d [2] 70 5c [2] 3e 50 [2] 32 5a [2] 25 51 [2] 3e 1f [2] 03 }

  condition:
    any of them
}