rule TTP_XOR_MULT_DOSStub_0d6b {
  strings:
    $key_0d6b = { 59 03 [2] 2d 1b [2] 6a 19 [2] 2d 08 [2] 63 04 [2] 6f 0e [2] 78 05 [2] 63 4b [2] 5e }

  condition:
    any of them
}