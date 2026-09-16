rule TTP_XOR_MULT_DOSStub_070e {
  strings:
    $key_070e = { 53 66 [2] 27 7e [2] 60 7c [2] 27 6d [2] 69 61 [2] 65 6b [2] 72 60 [2] 69 2e [2] 54 }

  condition:
    any of them
}