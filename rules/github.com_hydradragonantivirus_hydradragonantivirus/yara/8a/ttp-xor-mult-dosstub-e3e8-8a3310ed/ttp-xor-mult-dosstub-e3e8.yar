rule TTP_XOR_MULT_DOSStub_e3e8 {
  strings:
    $key_e3e8 = { b7 80 [2] c3 98 [2] 84 9a [2] c3 8b [2] 8d 87 [2] 81 8d [2] 96 86 [2] 8d c8 [2] b0 }

  condition:
    any of them
}