rule TTP_XOR_MULT_DOSStub_210f {
  strings:
    $key_210f = { 75 67 [2] 01 7f [2] 46 7d [2] 01 6c [2] 4f 60 [2] 43 6a [2] 54 61 [2] 4f 2f [2] 72 }

  condition:
    any of them
}