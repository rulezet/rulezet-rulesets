rule TTP_XOR_MULT_DOSStub_630e {
  strings:
    $key_630e = { 37 66 [2] 43 7e [2] 04 7c [2] 43 6d [2] 0d 61 [2] 01 6b [2] 16 60 [2] 0d 2e [2] 30 }

  condition:
    any of them
}