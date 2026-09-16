rule TTP_XOR_MULT_DOSStub_321f {
  strings:
    $key_321f = { 66 77 [2] 12 6f [2] 55 6d [2] 12 7c [2] 5c 70 [2] 50 7a [2] 47 71 [2] 5c 3f [2] 61 }

  condition:
    any of them
}