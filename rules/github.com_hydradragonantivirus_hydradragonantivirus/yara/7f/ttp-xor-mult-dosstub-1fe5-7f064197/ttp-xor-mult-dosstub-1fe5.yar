rule TTP_XOR_MULT_DOSStub_1fe5 {
  strings:
    $key_1fe5 = { 4b 8d [2] 3f 95 [2] 78 97 [2] 3f 86 [2] 71 8a [2] 7d 80 [2] 6a 8b [2] 71 c5 [2] 4c }

  condition:
    any of them
}