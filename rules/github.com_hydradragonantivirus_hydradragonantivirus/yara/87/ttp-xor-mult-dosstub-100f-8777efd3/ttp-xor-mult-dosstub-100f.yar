rule TTP_XOR_MULT_DOSStub_100f {
  strings:
    $key_100f = { 44 67 [2] 30 7f [2] 77 7d [2] 30 6c [2] 7e 60 [2] 72 6a [2] 65 61 [2] 7e 2f [2] 43 }

  condition:
    any of them
}