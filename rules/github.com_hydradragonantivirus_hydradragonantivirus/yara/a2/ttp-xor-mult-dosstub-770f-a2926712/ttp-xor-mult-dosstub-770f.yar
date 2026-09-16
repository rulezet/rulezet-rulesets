rule TTP_XOR_MULT_DOSStub_770f {
  strings:
    $key_770f = { 23 67 [2] 57 7f [2] 10 7d [2] 57 6c [2] 19 60 [2] 15 6a [2] 02 61 [2] 19 2f [2] 24 }

  condition:
    any of them
}