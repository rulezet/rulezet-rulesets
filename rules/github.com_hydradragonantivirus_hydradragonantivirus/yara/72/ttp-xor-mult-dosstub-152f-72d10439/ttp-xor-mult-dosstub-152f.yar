rule TTP_XOR_MULT_DOSStub_152f {
  strings:
    $key_152f = { 41 47 [2] 35 5f [2] 72 5d [2] 35 4c [2] 7b 40 [2] 77 4a [2] 60 41 [2] 7b 0f [2] 46 }

  condition:
    any of them
}