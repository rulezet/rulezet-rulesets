rule TTP_XOR_MULT_DOSStub_6d24 {
  strings:
    $key_6d24 = { 39 4c [2] 4d 54 [2] 0a 56 [2] 4d 47 [2] 03 4b [2] 0f 41 [2] 18 4a [2] 03 04 [2] 3e }

  condition:
    any of them
}