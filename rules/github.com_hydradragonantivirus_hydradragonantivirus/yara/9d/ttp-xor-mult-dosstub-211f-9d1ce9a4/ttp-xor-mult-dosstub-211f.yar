rule TTP_XOR_MULT_DOSStub_211f {
  strings:
    $key_211f = { 75 77 [2] 01 6f [2] 46 6d [2] 01 7c [2] 4f 70 [2] 43 7a [2] 54 71 [2] 4f 3f [2] 72 }

  condition:
    any of them
}