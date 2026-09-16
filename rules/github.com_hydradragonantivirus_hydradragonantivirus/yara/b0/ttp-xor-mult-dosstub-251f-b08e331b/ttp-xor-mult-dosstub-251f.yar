rule TTP_XOR_MULT_DOSStub_251f {
  strings:
    $key_251f = { 71 77 [2] 05 6f [2] 42 6d [2] 05 7c [2] 4b 70 [2] 47 7a [2] 50 71 [2] 4b 3f [2] 76 }

  condition:
    any of them
}