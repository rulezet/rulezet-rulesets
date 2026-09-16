rule TTP_XOR_MULT_DOSStub_2eae {
  strings:
    $key_2eae = { 7a c6 [2] 0e de [2] 49 dc [2] 0e cd [2] 40 c1 [2] 4c cb [2] 5b c0 [2] 40 8e [2] 7d }

  condition:
    any of them
}