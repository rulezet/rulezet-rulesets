rule TTP_XOR_MULT_DOSStub_121b {
  strings:
    $key_121b = { 46 73 [2] 32 6b [2] 75 69 [2] 32 78 [2] 7c 74 [2] 70 7e [2] 67 75 [2] 7c 3b [2] 41 }

  condition:
    any of them
}