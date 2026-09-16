rule TTP_XOR_MULT_DOSStub_0223 {
  strings:
    $key_0223 = { 56 4b [2] 22 53 [2] 65 51 [2] 22 40 [2] 6c 4c [2] 60 46 [2] 77 4d [2] 6c 03 [2] 51 }

  condition:
    any of them
}