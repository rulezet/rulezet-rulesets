rule TTP_XOR_MULT_DOSStub_3716 {
  strings:
    $key_3716 = { 63 7e [2] 17 66 [2] 50 64 [2] 17 75 [2] 59 79 [2] 55 73 [2] 42 78 [2] 59 36 [2] 64 }

  condition:
    any of them
}