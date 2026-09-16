rule TTP_XOR_MULT_DOSStub_310e {
  strings:
    $key_310e = { 65 66 [2] 11 7e [2] 56 7c [2] 11 6d [2] 5f 61 [2] 53 6b [2] 44 60 [2] 5f 2e [2] 62 }

  condition:
    any of them
}