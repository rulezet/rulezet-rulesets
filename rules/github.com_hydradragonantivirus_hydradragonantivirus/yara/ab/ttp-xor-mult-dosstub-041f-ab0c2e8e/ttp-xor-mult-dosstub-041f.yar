rule TTP_XOR_MULT_DOSStub_041f {
  strings:
    $key_041f = { 50 77 [2] 24 6f [2] 63 6d [2] 24 7c [2] 6a 70 [2] 66 7a [2] 71 71 [2] 6a 3f [2] 57 }

  condition:
    any of them
}