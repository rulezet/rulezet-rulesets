rule TTP_XOR_MULT_DOSStub_133f {
  strings:
    $key_133f = { 47 57 [2] 33 4f [2] 74 4d [2] 33 5c [2] 7d 50 [2] 71 5a [2] 66 51 [2] 7d 1f [2] 40 }

  condition:
    any of them
}