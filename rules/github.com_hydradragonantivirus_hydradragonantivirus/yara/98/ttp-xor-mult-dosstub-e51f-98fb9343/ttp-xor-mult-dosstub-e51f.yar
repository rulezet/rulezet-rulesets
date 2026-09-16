rule TTP_XOR_MULT_DOSStub_e51f {
  strings:
    $key_e51f = { b1 77 [2] c5 6f [2] 82 6d [2] c5 7c [2] 8b 70 [2] 87 7a [2] 90 71 [2] 8b 3f [2] b6 }

  condition:
    any of them
}