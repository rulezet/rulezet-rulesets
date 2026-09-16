rule TTP_XOR_MULT_DOSStub_5724 {
  strings:
    $key_5724 = { 03 4c [2] 77 54 [2] 30 56 [2] 77 47 [2] 39 4b [2] 35 41 [2] 22 4a [2] 39 04 [2] 04 }

  condition:
    any of them
}