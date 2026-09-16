rule TTP_XOR_MULT_DOSStub_cc90 {
  strings:
    $key_cc90 = { 98 f8 [2] ec e0 [2] ab e2 [2] ec f3 [2] a2 ff [2] ae f5 [2] b9 fe [2] a2 b0 [2] 9f }

  condition:
    any of them
}