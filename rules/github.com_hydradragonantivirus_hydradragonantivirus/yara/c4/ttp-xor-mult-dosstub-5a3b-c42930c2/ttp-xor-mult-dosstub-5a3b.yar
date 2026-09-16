rule TTP_XOR_MULT_DOSStub_5a3b {
  strings:
    $key_5a3b = { 0e 53 [2] 7a 4b [2] 3d 49 [2] 7a 58 [2] 34 54 [2] 38 5e [2] 2f 55 [2] 34 1b [2] 09 }

  condition:
    any of them
}