rule TTP_XOR_MULT_DOSStub_1fe3 {
  strings:
    $key_1fe3 = { 4b 8b [2] 3f 93 [2] 78 91 [2] 3f 80 [2] 71 8c [2] 7d 86 [2] 6a 8d [2] 71 c3 [2] 4c }

  condition:
    any of them
}