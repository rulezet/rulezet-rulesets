rule TTP_XOR_MULT_DOSStub_3053 {
  strings:
    $key_3053 = { 64 3b [2] 10 23 [2] 57 21 [2] 10 30 [2] 5e 3c [2] 52 36 [2] 45 3d [2] 5e 73 [2] 63 }

  condition:
    any of them
}