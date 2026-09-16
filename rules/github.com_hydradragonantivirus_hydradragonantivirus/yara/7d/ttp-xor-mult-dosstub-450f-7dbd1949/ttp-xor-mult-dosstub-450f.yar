rule TTP_XOR_MULT_DOSStub_450f {
  strings:
    $key_450f = { 11 67 [2] 65 7f [2] 22 7d [2] 65 6c [2] 2b 60 [2] 27 6a [2] 30 61 [2] 2b 2f [2] 16 }

  condition:
    any of them
}