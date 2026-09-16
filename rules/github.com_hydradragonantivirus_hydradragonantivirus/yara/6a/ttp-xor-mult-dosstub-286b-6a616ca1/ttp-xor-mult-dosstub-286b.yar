rule TTP_XOR_MULT_DOSStub_286b {
  strings:
    $key_286b = { 7c 03 [2] 08 1b [2] 4f 19 [2] 08 08 [2] 46 04 [2] 4a 0e [2] 5d 05 [2] 46 4b [2] 7b }

  condition:
    any of them
}