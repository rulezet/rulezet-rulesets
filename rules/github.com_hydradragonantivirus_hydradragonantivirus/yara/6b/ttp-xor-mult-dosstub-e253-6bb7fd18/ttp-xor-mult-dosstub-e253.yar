rule TTP_XOR_MULT_DOSStub_e253 {
  strings:
    $key_e253 = { b6 3b [2] c2 23 [2] 85 21 [2] c2 30 [2] 8c 3c [2] 80 36 [2] 97 3d [2] 8c 73 [2] b1 }

  condition:
    any of them
}