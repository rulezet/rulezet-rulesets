rule TTP_XOR_MULT_DOSStub_561b {
  strings:
    $key_561b = { 02 73 [2] 76 6b [2] 31 69 [2] 76 78 [2] 38 74 [2] 34 7e [2] 23 75 [2] 38 3b [2] 05 }

  condition:
    any of them
}