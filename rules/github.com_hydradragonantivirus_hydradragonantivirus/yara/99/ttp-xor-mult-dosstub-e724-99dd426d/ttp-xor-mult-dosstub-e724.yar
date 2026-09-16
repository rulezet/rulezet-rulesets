rule TTP_XOR_MULT_DOSStub_e724 {
  strings:
    $key_e724 = { b3 4c [2] c7 54 [2] 80 56 [2] c7 47 [2] 89 4b [2] 85 41 [2] 92 4a [2] 89 04 [2] b4 }

  condition:
    any of them
}