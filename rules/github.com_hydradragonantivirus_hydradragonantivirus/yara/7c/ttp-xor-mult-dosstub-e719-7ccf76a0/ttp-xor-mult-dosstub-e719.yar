rule TTP_XOR_MULT_DOSStub_e719 {
  strings:
    $key_e719 = { b3 71 [2] c7 69 [2] 80 6b [2] c7 7a [2] 89 76 [2] 85 7c [2] 92 77 [2] 89 39 [2] b4 }

  condition:
    any of them
}