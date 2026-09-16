rule TTP_XOR_MULT_DOSStub_1e6b {
  strings:
    $key_1e6b = { 4a 03 [2] 3e 1b [2] 79 19 [2] 3e 08 [2] 70 04 [2] 7c 0e [2] 6b 05 [2] 70 4b [2] 4d }

  condition:
    any of them
}