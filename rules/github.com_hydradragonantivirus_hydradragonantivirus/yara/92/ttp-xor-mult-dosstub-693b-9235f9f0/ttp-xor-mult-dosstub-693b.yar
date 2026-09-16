rule TTP_XOR_MULT_DOSStub_693b {
  strings:
    $key_693b = { 3d 53 [2] 49 4b [2] 0e 49 [2] 49 58 [2] 07 54 [2] 0b 5e [2] 1c 55 [2] 07 1b [2] 3a }

  condition:
    any of them
}