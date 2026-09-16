rule TTP_XOR_MULT_DOSStub_e72f {
  strings:
    $key_e72f = { b3 47 [2] c7 5f [2] 80 5d [2] c7 4c [2] 89 40 [2] 85 4a [2] 92 41 [2] 89 0f [2] b4 }

  condition:
    any of them
}