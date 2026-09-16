rule TTP_XOR_MULT_DOSStub_4826 {
  strings:
    $key_4826 = { 1c 4e [2] 68 56 [2] 2f 54 [2] 68 45 [2] 26 49 [2] 2a 43 [2] 3d 48 [2] 26 06 [2] 1b }

  condition:
    any of them
}