rule TTP_XOR_MULT_DOSStub_016b {
  strings:
    $key_016b = { 55 03 [2] 21 1b [2] 66 19 [2] 21 08 [2] 6f 04 [2] 63 0e [2] 74 05 [2] 6f 4b [2] 52 }

  condition:
    any of them
}