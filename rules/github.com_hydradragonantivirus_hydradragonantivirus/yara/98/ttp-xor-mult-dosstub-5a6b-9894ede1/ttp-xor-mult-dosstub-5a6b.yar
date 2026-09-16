rule TTP_XOR_MULT_DOSStub_5a6b {
  strings:
    $key_5a6b = { 0e 03 [2] 7a 1b [2] 3d 19 [2] 7a 08 [2] 34 04 [2] 38 0e [2] 2f 05 [2] 34 4b [2] 09 }

  condition:
    any of them
}