rule TTP_XOR_MULT_DOSStub_203b {
  strings:
    $key_203b = { 74 53 [2] 00 4b [2] 47 49 [2] 00 58 [2] 4e 54 [2] 42 5e [2] 55 55 [2] 4e 1b [2] 73 }

  condition:
    any of them
}