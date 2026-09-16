rule TTP_XOR_MULT_DOSStub_e774 {
  strings:
    $key_e774 = { b3 1c [2] c7 04 [2] 80 06 [2] c7 17 [2] 89 1b [2] 85 11 [2] 92 1a [2] 89 54 [2] b4 }

  condition:
    any of them
}