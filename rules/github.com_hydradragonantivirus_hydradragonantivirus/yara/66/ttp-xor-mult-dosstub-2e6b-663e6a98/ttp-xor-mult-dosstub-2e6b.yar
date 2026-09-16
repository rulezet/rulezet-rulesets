rule TTP_XOR_MULT_DOSStub_2e6b {
  strings:
    $key_2e6b = { 7a 03 [2] 0e 1b [2] 49 19 [2] 0e 08 [2] 40 04 [2] 4c 0e [2] 5b 05 [2] 40 4b [2] 7d }

  condition:
    any of them
}