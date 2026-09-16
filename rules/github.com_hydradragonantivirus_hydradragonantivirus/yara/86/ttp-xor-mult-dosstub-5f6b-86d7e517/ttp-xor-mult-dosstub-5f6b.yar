rule TTP_XOR_MULT_DOSStub_5f6b {
  strings:
    $key_5f6b = { 0b 03 [2] 7f 1b [2] 38 19 [2] 7f 08 [2] 31 04 [2] 3d 0e [2] 2a 05 [2] 31 4b [2] 0c }

  condition:
    any of them
}