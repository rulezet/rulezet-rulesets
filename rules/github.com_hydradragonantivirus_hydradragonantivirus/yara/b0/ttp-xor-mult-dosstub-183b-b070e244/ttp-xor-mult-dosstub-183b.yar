rule TTP_XOR_MULT_DOSStub_183b {
  strings:
    $key_183b = { 4c 53 [2] 38 4b [2] 7f 49 [2] 38 58 [2] 76 54 [2] 7a 5e [2] 6d 55 [2] 76 1b [2] 4b }

  condition:
    any of them
}