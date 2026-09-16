rule TTP_XOR_MULT_DOSStub_212f {
  strings:
    $key_212f = { 75 47 [2] 01 5f [2] 46 5d [2] 01 4c [2] 4f 40 [2] 43 4a [2] 54 41 [2] 4f 0f [2] 72 }

  condition:
    any of them
}