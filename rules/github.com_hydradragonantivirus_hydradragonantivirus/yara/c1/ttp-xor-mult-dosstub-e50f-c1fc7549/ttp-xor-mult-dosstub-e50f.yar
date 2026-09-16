rule TTP_XOR_MULT_DOSStub_e50f {
  strings:
    $key_e50f = { b1 67 [2] c5 7f [2] 82 7d [2] c5 6c [2] 8b 60 [2] 87 6a [2] 90 61 [2] 8b 2f [2] b6 }

  condition:
    any of them
}