rule TTP_XOR_MULT_DOSStub_c513 {
  strings:
    $key_c513 = { 91 7b [2] e5 63 [2] a2 61 [2] e5 70 [2] ab 7c [2] a7 76 [2] b0 7d [2] ab 33 [2] 96 }

  condition:
    any of them
}