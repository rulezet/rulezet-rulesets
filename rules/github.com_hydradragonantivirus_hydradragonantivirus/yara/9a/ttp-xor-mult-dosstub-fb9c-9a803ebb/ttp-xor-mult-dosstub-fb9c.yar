rule TTP_XOR_MULT_DOSStub_fb9c {
  strings:
    $key_fb9c = { af f4 [2] db ec [2] 9c ee [2] db ff [2] 95 f3 [2] 99 f9 [2] 8e f2 [2] 95 bc [2] a8 }

  condition:
    any of them
}