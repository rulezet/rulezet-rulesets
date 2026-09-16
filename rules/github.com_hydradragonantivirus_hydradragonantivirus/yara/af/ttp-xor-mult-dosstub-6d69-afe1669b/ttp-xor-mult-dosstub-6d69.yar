rule TTP_XOR_MULT_DOSStub_6d69 {
  strings:
    $key_6d69 = { 39 01 [2] 4d 19 [2] 0a 1b [2] 4d 0a [2] 03 06 [2] 0f 0c [2] 18 07 [2] 03 49 [2] 3e }

  condition:
    any of them
}