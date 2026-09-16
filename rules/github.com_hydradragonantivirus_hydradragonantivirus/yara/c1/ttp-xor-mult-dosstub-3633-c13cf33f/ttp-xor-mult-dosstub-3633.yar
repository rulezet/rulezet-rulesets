rule TTP_XOR_MULT_DOSStub_3633 {
  strings:
    $key_3633 = { 62 5b [2] 16 43 [2] 51 41 [2] 16 50 [2] 58 5c [2] 54 56 [2] 43 5d [2] 58 13 [2] 65 }

  condition:
    any of them
}