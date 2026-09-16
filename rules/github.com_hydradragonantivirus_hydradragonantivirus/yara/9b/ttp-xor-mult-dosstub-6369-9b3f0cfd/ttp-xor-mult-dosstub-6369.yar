rule TTP_XOR_MULT_DOSStub_6369 {
  strings:
    $key_6369 = { 37 01 [2] 43 19 [2] 04 1b [2] 43 0a [2] 0d 06 [2] 01 0c [2] 16 07 [2] 0d 49 [2] 30 }

  condition:
    any of them
}