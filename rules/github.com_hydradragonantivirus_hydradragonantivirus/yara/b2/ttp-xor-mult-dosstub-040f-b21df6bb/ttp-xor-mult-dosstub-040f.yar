rule TTP_XOR_MULT_DOSStub_040f {
  strings:
    $key_040f = { 50 67 [2] 24 7f [2] 63 7d [2] 24 6c [2] 6a 60 [2] 66 6a [2] 71 61 [2] 6a 2f [2] 57 }

  condition:
    any of them
}