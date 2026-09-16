rule TTP_XOR_MULT_DOSStub_223f {
  strings:
    $key_223f = { 76 57 [2] 02 4f [2] 45 4d [2] 02 5c [2] 4c 50 [2] 40 5a [2] 57 51 [2] 4c 1f [2] 71 }

  condition:
    any of them
}