rule TTP_XOR_MULT_DOSStub_520f {
  strings:
    $key_520f = { 06 67 [2] 72 7f [2] 35 7d [2] 72 6c [2] 3c 60 [2] 30 6a [2] 27 61 [2] 3c 2f [2] 01 }

  condition:
    any of them
}