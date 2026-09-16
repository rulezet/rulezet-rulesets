rule TTP_XOR_MULT_DOSStub_e02f {
  strings:
    $key_e02f = { b4 47 [2] c0 5f [2] 87 5d [2] c0 4c [2] 8e 40 [2] 82 4a [2] 95 41 [2] 8e 0f [2] b3 }

  condition:
    any of them
}