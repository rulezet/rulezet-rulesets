rule TTP_XOR_MULT_DOSStub_483b {
  strings:
    $key_483b = { 1c 53 [2] 68 4b [2] 2f 49 [2] 68 58 [2] 26 54 [2] 2a 5e [2] 3d 55 [2] 26 1b [2] 1b }

  condition:
    any of them
}