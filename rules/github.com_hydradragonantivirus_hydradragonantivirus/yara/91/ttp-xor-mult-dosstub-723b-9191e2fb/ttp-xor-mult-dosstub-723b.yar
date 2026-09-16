rule TTP_XOR_MULT_DOSStub_723b {
  strings:
    $key_723b = { 26 53 [2] 52 4b [2] 15 49 [2] 52 58 [2] 1c 54 [2] 10 5e [2] 07 55 [2] 1c 1b [2] 21 }

  condition:
    any of them
}