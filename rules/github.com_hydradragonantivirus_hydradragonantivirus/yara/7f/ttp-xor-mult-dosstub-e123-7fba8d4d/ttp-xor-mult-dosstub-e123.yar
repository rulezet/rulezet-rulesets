rule TTP_XOR_MULT_DOSStub_e123 {
  strings:
    $key_e123 = { b5 4b [2] c1 53 [2] 86 51 [2] c1 40 [2] 8f 4c [2] 83 46 [2] 94 4d [2] 8f 03 [2] b2 }

  condition:
    any of them
}