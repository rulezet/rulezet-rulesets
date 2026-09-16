rule TTP_XOR_MULT_DOSStub_226b {
  strings:
    $key_226b = { 76 03 [2] 02 1b [2] 45 19 [2] 02 08 [2] 4c 04 [2] 40 0e [2] 57 05 [2] 4c 4b [2] 71 }

  condition:
    any of them
}