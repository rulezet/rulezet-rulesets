rule TTP_XOR_MULT_DOSStub_e423 {
  strings:
    $key_e423 = { b0 4b [2] c4 53 [2] 83 51 [2] c4 40 [2] 8a 4c [2] 86 46 [2] 91 4d [2] 8a 03 [2] b7 }

  condition:
    any of them
}