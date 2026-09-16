rule TTP_XOR_MULT_DOSStub_5eae {
  strings:
    $key_5eae = { 0a c6 [2] 7e de [2] 39 dc [2] 7e cd [2] 30 c1 [2] 3c cb [2] 2b c0 [2] 30 8e [2] 0d }

  condition:
    any of them
}