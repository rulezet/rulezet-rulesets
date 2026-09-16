rule TTP_XOR_MULT_DOSStub_1f33 {
  strings:
    $key_1f33 = { 4b 5b [2] 3f 43 [2] 78 41 [2] 3f 50 [2] 71 5c [2] 7d 56 [2] 6a 5d [2] 71 13 [2] 4c }

  condition:
    any of them
}