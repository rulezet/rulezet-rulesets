rule TTP_XOR_MULT_DOSStub_e723 {
  strings:
    $key_e723 = { b3 4b [2] c7 53 [2] 80 51 [2] c7 40 [2] 89 4c [2] 85 46 [2] 92 4d [2] 89 03 [2] b4 }

  condition:
    any of them
}