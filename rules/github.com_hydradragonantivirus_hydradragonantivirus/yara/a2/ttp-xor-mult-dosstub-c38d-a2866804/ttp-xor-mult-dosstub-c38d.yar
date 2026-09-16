rule TTP_XOR_MULT_DOSStub_c38d {
  strings:
    $key_c38d = { 97 e5 [2] e3 fd [2] a4 ff [2] e3 ee [2] ad e2 [2] a1 e8 [2] b6 e3 [2] ad ad [2] 90 }

  condition:
    any of them
}