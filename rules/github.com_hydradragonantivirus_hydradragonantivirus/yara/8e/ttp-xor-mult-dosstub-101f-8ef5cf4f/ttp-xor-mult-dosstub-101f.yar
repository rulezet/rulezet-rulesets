rule TTP_XOR_MULT_DOSStub_101f {
  strings:
    $key_101f = { 44 77 [2] 30 6f [2] 77 6d [2] 30 7c [2] 7e 70 [2] 72 7a [2] 65 71 [2] 7e 3f [2] 43 }

  condition:
    any of them
}