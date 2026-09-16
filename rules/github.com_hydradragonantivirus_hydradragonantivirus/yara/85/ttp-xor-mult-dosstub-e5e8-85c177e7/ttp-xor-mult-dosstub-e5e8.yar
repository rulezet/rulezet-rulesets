rule TTP_XOR_MULT_DOSStub_e5e8 {
  strings:
    $key_e5e8 = { b1 80 [2] c5 98 [2] 82 9a [2] c5 8b [2] 8b 87 [2] 87 8d [2] 90 86 [2] 8b c8 [2] b6 }

  condition:
    any of them
}