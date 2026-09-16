rule TTP_XOR_MULT_DOSStub_e769 {
  strings:
    $key_e769 = { b3 01 [2] c7 19 [2] 80 1b [2] c7 0a [2] 89 06 [2] 85 0c [2] 92 07 [2] 89 49 [2] b4 }

  condition:
    any of them
}