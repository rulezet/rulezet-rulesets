rule TTP_XOR_MULT_DOSStub_ea91 {
  strings:
    $key_ea91 = { be f9 [2] ca e1 [2] 8d e3 [2] ca f2 [2] 84 fe [2] 88 f4 [2] 9f ff [2] 84 b1 [2] b9 }

  condition:
    any of them
}