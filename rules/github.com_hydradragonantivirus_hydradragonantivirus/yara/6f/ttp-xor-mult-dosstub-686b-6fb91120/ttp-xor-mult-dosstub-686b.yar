rule TTP_XOR_MULT_DOSStub_686b {
  strings:
    $key_686b = { 3c 03 [2] 48 1b [2] 0f 19 [2] 48 08 [2] 06 04 [2] 0a 0e [2] 1d 05 [2] 06 4b [2] 3b }

  condition:
    any of them
}