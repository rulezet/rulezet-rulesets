rule TTP_XOR_MULT_DOSStub_482b {
  strings:
    $key_482b = { 1c 43 [2] 68 5b [2] 2f 59 [2] 68 48 [2] 26 44 [2] 2a 4e [2] 3d 45 [2] 26 0b [2] 1b }

  condition:
    any of them
}