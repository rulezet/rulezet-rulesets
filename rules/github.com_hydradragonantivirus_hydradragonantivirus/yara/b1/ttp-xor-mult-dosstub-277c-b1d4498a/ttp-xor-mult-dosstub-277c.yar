rule TTP_XOR_MULT_DOSStub_277c {
  strings:
    $key_277c = { 73 14 [2] 07 0c [2] 40 0e [2] 07 1f [2] 49 13 [2] 45 19 [2] 52 12 [2] 49 5c [2] 74 }

  condition:
    any of them
}