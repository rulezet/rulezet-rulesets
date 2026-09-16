rule TTP_XOR_MULT_DOSStub_e71f {
  strings:
    $key_e71f = { b3 77 [2] c7 6f [2] 80 6d [2] c7 7c [2] 89 70 [2] 85 7a [2] 92 71 [2] 89 3f [2] b4 }

  condition:
    any of them
}