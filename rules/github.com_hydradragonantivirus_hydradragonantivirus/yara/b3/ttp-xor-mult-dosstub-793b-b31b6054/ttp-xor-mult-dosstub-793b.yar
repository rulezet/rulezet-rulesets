rule TTP_XOR_MULT_DOSStub_793b {
  strings:
    $key_793b = { 2d 53 [2] 59 4b [2] 1e 49 [2] 59 58 [2] 17 54 [2] 1b 5e [2] 0c 55 [2] 17 1b [2] 2a }

  condition:
    any of them
}