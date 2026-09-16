rule TTP_XOR_MULT_DOSStub_2529 {
  strings:
    $key_2529 = { 71 41 [2] 05 59 [2] 42 5b [2] 05 4a [2] 4b 46 [2] 47 4c [2] 50 47 [2] 4b 09 [2] 76 }

  condition:
    any of them
}