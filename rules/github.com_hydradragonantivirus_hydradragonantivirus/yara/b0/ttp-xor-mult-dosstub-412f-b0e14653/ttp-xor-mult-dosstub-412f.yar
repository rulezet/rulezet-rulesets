rule TTP_XOR_MULT_DOSStub_412f {
  strings:
    $key_412f = { 15 47 [2] 61 5f [2] 26 5d [2] 61 4c [2] 2f 40 [2] 23 4a [2] 34 41 [2] 2f 0f [2] 12 }

  condition:
    any of them
}