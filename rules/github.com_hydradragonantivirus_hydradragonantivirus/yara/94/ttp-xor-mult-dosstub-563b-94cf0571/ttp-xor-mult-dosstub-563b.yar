rule TTP_XOR_MULT_DOSStub_563b {
  strings:
    $key_563b = { 02 53 [2] 76 4b [2] 31 49 [2] 76 58 [2] 38 54 [2] 34 5e [2] 23 55 [2] 38 1b [2] 05 }

  condition:
    any of them
}