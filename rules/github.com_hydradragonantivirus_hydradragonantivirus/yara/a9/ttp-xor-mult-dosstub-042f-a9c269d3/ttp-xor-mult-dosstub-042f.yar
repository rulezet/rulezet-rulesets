rule TTP_XOR_MULT_DOSStub_042f {
  strings:
    $key_042f = { 50 47 [2] 24 5f [2] 63 5d [2] 24 4c [2] 6a 40 [2] 66 4a [2] 71 41 [2] 6a 0f [2] 57 }

  condition:
    any of them
}