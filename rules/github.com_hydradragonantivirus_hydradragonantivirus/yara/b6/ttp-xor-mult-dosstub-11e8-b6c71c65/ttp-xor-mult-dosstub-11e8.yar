rule TTP_XOR_MULT_DOSStub_11e8 {
  strings:
    $key_11e8 = { 45 80 [2] 31 98 [2] 76 9a [2] 31 8b [2] 7f 87 [2] 73 8d [2] 64 86 [2] 7f c8 [2] 42 }

  condition:
    any of them
}