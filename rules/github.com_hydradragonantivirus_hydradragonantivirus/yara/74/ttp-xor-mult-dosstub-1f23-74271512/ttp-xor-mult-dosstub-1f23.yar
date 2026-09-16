rule TTP_XOR_MULT_DOSStub_1f23 {
  strings:
    $key_1f23 = { 4b 4b [2] 3f 53 [2] 78 51 [2] 3f 40 [2] 71 4c [2] 7d 46 [2] 6a 4d [2] 71 03 [2] 4c }

  condition:
    any of them
}