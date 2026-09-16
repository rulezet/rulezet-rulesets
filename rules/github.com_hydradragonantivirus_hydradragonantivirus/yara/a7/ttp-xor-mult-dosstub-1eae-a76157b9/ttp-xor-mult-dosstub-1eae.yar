rule TTP_XOR_MULT_DOSStub_1eae {
  strings:
    $key_1eae = { 4a c6 [2] 3e de [2] 79 dc [2] 3e cd [2] 70 c1 [2] 7c cb [2] 6b c0 [2] 70 8e [2] 4d }

  condition:
    any of them
}