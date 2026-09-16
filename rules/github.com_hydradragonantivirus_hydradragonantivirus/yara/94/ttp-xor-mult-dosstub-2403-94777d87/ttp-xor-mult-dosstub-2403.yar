rule TTP_XOR_MULT_DOSStub_2403 {
  strings:
    $key_2403 = { 70 6b [2] 04 73 [2] 43 71 [2] 04 60 [2] 4a 6c [2] 46 66 [2] 51 6d [2] 4a 23 [2] 77 }

  condition:
    any of them
}