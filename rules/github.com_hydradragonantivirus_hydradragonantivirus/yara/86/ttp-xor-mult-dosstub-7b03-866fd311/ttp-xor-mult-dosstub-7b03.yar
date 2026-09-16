rule TTP_XOR_MULT_DOSStub_7b03 {
  strings:
    $key_7b03 = { 2f 6b [2] 5b 73 [2] 1c 71 [2] 5b 60 [2] 15 6c [2] 19 66 [2] 0e 6d [2] 15 23 [2] 28 }

  condition:
    any of them
}