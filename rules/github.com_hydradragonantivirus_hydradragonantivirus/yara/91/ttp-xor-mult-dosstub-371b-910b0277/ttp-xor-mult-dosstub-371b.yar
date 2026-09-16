rule TTP_XOR_MULT_DOSStub_371b {
  strings:
    $key_371b = { 63 73 [2] 17 6b [2] 50 69 [2] 17 78 [2] 59 74 [2] 55 7e [2] 42 75 [2] 59 3b [2] 64 }

  condition:
    any of them
}