rule TTP_XOR_MULT_DOSStub_1903 {
  strings:
    $key_1903 = { 4d 6b [2] 39 73 [2] 7e 71 [2] 39 60 [2] 77 6c [2] 7b 66 [2] 6c 6d [2] 77 23 [2] 4a }

  condition:
    any of them
}