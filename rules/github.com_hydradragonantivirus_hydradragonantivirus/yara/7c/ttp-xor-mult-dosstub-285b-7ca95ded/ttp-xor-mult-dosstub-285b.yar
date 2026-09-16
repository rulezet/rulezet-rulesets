rule TTP_XOR_MULT_DOSStub_285b {
  strings:
    $key_285b = { 7c 33 [2] 08 2b [2] 4f 29 [2] 08 38 [2] 46 34 [2] 4a 3e [2] 5d 35 [2] 46 7b [2] 7b }

  condition:
    any of them
}