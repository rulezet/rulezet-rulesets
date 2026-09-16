rule TTP_XOR_MULT_DOSStub_51e3 {
  strings:
    $key_51e3 = { 05 8b [2] 71 93 [2] 36 91 [2] 71 80 [2] 3f 8c [2] 33 86 [2] 24 8d [2] 3f c3 [2] 02 }

  condition:
    any of them
}