rule TTP_XOR_MULT_DOSStub_e753 {
  strings:
    $key_e753 = { b3 3b [2] c7 23 [2] 80 21 [2] c7 30 [2] 89 3c [2] 85 36 [2] 92 3d [2] 89 73 [2] b4 }

  condition:
    any of them
}