rule TTP_XOR_MULT_DOSStub_5f1f {
  strings:
    $key_5f1f = { 0b 77 [2] 7f 6f [2] 38 6d [2] 7f 7c [2] 31 70 [2] 3d 7a [2] 2a 71 [2] 31 3f [2] 0c }

  condition:
    any of them
}