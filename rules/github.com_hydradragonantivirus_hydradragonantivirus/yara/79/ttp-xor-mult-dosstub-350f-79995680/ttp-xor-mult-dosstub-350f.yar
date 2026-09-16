rule TTP_XOR_MULT_DOSStub_350f {
  strings:
    $key_350f = { 61 67 [2] 15 7f [2] 52 7d [2] 15 6c [2] 5b 60 [2] 57 6a [2] 40 61 [2] 5b 2f [2] 66 }

  condition:
    any of them
}