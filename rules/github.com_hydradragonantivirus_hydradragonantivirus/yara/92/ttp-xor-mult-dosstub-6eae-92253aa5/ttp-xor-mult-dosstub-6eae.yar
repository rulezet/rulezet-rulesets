rule TTP_XOR_MULT_DOSStub_6eae {
  strings:
    $key_6eae = { 3a c6 [2] 4e de [2] 09 dc [2] 4e cd [2] 00 c1 [2] 0c cb [2] 1b c0 [2] 00 8e [2] 3d }

  condition:
    any of them
}