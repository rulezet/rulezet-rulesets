rule TTP_XOR_MULT_DOSStub_2b19 {
  strings:
    $key_2b19 = { 7f 71 [2] 0b 69 [2] 4c 6b [2] 0b 7a [2] 45 76 [2] 49 7c [2] 5e 77 [2] 45 39 [2] 78 }

  condition:
    any of them
}