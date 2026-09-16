rule TTP_XOR_MULT_DOSStub_2505 {
  strings:
    $key_2505 = { 71 6d [2] 05 75 [2] 42 77 [2] 05 66 [2] 4b 6a [2] 47 60 [2] 50 6b [2] 4b 25 [2] 76 }

  condition:
    any of them
}