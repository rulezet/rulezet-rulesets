rule TTP_XOR_MULT_DOSStub_1f22 {
  strings:
    $key_1f22 = { 4b 4a [2] 3f 52 [2] 78 50 [2] 3f 41 [2] 71 4d [2] 7d 47 [2] 6a 4c [2] 71 02 [2] 4c }

  condition:
    any of them
}