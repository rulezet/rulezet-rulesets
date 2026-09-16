rule TTP_XOR_MULT_DOSStub_241b {
  strings:
    $key_241b = { 70 73 [2] 04 6b [2] 43 69 [2] 04 78 [2] 4a 74 [2] 46 7e [2] 51 75 [2] 4a 3b [2] 77 }

  condition:
    any of them
}