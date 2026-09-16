rule TTP_XOR_MULT_DOSStub_e025 {
  strings:
    $key_e025 = { b4 4d [2] c0 55 [2] 87 57 [2] c0 46 [2] 8e 4a [2] 82 40 [2] 95 4b [2] 8e 05 [2] b3 }

  condition:
    any of them
}