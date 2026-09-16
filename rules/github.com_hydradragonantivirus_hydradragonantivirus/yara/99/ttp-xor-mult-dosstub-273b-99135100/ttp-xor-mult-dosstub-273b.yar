rule TTP_XOR_MULT_DOSStub_273b {
  strings:
    $key_273b = { 73 53 [2] 07 4b [2] 40 49 [2] 07 58 [2] 49 54 [2] 45 5e [2] 52 55 [2] 49 1b [2] 74 }

  condition:
    any of them
}