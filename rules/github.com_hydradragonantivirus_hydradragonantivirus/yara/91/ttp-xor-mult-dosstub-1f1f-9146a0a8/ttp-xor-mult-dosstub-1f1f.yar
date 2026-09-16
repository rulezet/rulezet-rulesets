rule TTP_XOR_MULT_DOSStub_1f1f {
  strings:
    $key_1f1f = { 4b 77 [2] 3f 6f [2] 78 6d [2] 3f 7c [2] 71 70 [2] 7d 7a [2] 6a 71 [2] 71 3f [2] 4c }

  condition:
    any of them
}