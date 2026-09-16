rule TTP_XOR_MULT_DOSStub_1f13 {
  strings:
    $key_1f13 = { 4b 7b [2] 3f 63 [2] 78 61 [2] 3f 70 [2] 71 7c [2] 7d 76 [2] 6a 7d [2] 71 33 [2] 4c }

  condition:
    any of them
}