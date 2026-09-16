rule TTP_XOR_MULT_DOSStub_6d23 {
  strings:
    $key_6d23 = { 39 4b [2] 4d 53 [2] 0a 51 [2] 4d 40 [2] 03 4c [2] 0f 46 [2] 18 4d [2] 03 03 [2] 3e }

  condition:
    any of them
}