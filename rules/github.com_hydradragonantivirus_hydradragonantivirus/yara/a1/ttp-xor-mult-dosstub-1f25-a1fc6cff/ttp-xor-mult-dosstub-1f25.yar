rule TTP_XOR_MULT_DOSStub_1f25 {
  strings:
    $key_1f25 = { 4b 4d [2] 3f 55 [2] 78 57 [2] 3f 46 [2] 71 4a [2] 7d 40 [2] 6a 4b [2] 71 05 [2] 4c }

  condition:
    any of them
}