rule TTP_XOR_MULT_DOSStub_51e8 {
  strings:
    $key_51e8 = { 05 80 [2] 71 98 [2] 36 9a [2] 71 8b [2] 3f 87 [2] 33 8d [2] 24 86 [2] 3f c8 [2] 02 }

  condition:
    any of them
}