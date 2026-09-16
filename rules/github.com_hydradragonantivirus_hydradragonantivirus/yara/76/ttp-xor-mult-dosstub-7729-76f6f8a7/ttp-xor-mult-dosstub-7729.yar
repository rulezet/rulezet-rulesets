rule TTP_XOR_MULT_DOSStub_7729 {
  strings:
    $key_7729 = { 23 41 [2] 57 59 [2] 10 5b [2] 57 4a [2] 19 46 [2] 15 4c [2] 02 47 [2] 19 09 [2] 24 }

  condition:
    any of them
}