rule TTP_XOR_MULT_DOSStub_126b {
  strings:
    $key_126b = { 46 03 [2] 32 1b [2] 75 19 [2] 32 08 [2] 7c 04 [2] 70 0e [2] 67 05 [2] 7c 4b [2] 41 }

  condition:
    any of them
}