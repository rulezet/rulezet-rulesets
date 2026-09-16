rule TTP_XOR_MULT_DOSStub_2513 {
  strings:
    $key_2513 = { 71 7b [2] 05 63 [2] 42 61 [2] 05 70 [2] 4b 7c [2] 47 76 [2] 50 7d [2] 4b 33 [2] 76 }

  condition:
    any of them
}