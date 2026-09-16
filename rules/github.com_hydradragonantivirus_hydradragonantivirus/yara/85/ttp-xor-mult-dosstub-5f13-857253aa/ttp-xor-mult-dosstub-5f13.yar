rule TTP_XOR_MULT_DOSStub_5f13 {
  strings:
    $key_5f13 = { 0b 7b [2] 7f 63 [2] 38 61 [2] 7f 70 [2] 31 7c [2] 3d 76 [2] 2a 7d [2] 31 33 [2] 0c }

  condition:
    any of them
}