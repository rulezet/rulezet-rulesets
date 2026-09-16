rule TTP_XOR_MULT_DOSStub_6e31 {
  strings:
    $key_6e31 = { 3a 59 [2] 4e 41 [2] 09 43 [2] 4e 52 [2] 00 5e [2] 0c 54 [2] 1b 5f [2] 00 11 [2] 3d }

  condition:
    any of them
}