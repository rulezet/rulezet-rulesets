rule TTP_XOR_MULT_DOSStub_6d29 {
  strings:
    $key_6d29 = { 39 41 [2] 4d 59 [2] 0a 5b [2] 4d 4a [2] 03 46 [2] 0f 4c [2] 18 47 [2] 03 09 [2] 3e }

  condition:
    any of them
}