rule TTP_XOR_MULT_DOSStub_4d23 {
  strings:
    $key_4d23 = { 19 4b [2] 6d 53 [2] 2a 51 [2] 6d 40 [2] 23 4c [2] 2f 46 [2] 38 4d [2] 23 03 [2] 1e }

  condition:
    any of them
}