rule TTP_XOR_MULT_DOSStub_5703 {
  strings:
    $key_5703 = { 03 6b [2] 77 73 [2] 30 71 [2] 77 60 [2] 39 6c [2] 35 66 [2] 22 6d [2] 39 23 [2] 04 }

  condition:
    any of them
}