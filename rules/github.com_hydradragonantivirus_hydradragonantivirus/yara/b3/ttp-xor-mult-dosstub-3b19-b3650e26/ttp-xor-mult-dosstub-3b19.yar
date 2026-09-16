rule TTP_XOR_MULT_DOSStub_3b19 {
  strings:
    $key_3b19 = { 6f 71 [2] 1b 69 [2] 5c 6b [2] 1b 7a [2] 55 76 [2] 59 7c [2] 4e 77 [2] 55 39 [2] 68 }

  condition:
    any of them
}