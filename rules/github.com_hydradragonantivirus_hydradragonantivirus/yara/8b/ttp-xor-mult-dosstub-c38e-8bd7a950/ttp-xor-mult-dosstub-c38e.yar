rule TTP_XOR_MULT_DOSStub_c38e {
  strings:
    $key_c38e = { 97 e6 [2] e3 fe [2] a4 fc [2] e3 ed [2] ad e1 [2] a1 eb [2] b6 e0 [2] ad ae [2] 90 }

  condition:
    any of them
}