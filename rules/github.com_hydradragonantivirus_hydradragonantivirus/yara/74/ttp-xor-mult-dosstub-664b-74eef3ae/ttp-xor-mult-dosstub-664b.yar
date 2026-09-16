rule TTP_XOR_MULT_DOSStub_664b {
  strings:
    $key_664b = { 32 23 [2] 46 3b [2] 01 39 [2] 46 28 [2] 08 24 [2] 04 2e [2] 13 25 [2] 08 6b [2] 35 }

  condition:
    any of them
}