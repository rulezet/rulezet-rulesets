rule TTP_XOR_MULT_DOSStub_486b {
  strings:
    $key_486b = { 1c 03 [2] 68 1b [2] 2f 19 [2] 68 08 [2] 26 04 [2] 2a 0e [2] 3d 05 [2] 26 4b [2] 1b }

  condition:
    any of them
}