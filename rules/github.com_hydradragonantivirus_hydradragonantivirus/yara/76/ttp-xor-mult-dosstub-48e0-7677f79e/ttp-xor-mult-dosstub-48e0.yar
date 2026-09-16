rule TTP_XOR_MULT_DOSStub_48e0 {
  strings:
    $key_48e0 = { 1c 88 [2] 68 90 [2] 2f 92 [2] 68 83 [2] 26 8f [2] 2a 85 [2] 3d 8e [2] 26 c0 [2] 1b }

  condition:
    any of them
}