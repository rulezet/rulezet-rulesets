rule TTP_XOR_MULT_DOSStub_6e6b {
  strings:
    $key_6e6b = { 3a 03 [2] 4e 1b [2] 09 19 [2] 4e 08 [2] 00 04 [2] 0c 0e [2] 1b 05 [2] 00 4b [2] 3d }

  condition:
    any of them
}