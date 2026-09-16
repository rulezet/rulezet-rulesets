rule TTP_XOR_MULT_DOSStub_1f3f {
  strings:
    $key_1f3f = { 4b 57 [2] 3f 4f [2] 78 4d [2] 3f 5c [2] 71 50 [2] 7d 5a [2] 6a 51 [2] 71 1f [2] 4c }

  condition:
    any of them
}