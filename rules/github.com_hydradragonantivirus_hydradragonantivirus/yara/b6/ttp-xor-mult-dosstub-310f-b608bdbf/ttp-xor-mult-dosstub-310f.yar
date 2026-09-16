rule TTP_XOR_MULT_DOSStub_310f {
  strings:
    $key_310f = { 65 67 [2] 11 7f [2] 56 7d [2] 11 6c [2] 5f 60 [2] 53 6a [2] 44 61 [2] 5f 2f [2] 62 }

  condition:
    any of them
}