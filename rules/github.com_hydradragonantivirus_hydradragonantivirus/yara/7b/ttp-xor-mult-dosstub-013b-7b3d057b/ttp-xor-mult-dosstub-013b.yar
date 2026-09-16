rule TTP_XOR_MULT_DOSStub_013b {
  strings:
    $key_013b = { 55 53 [2] 21 4b [2] 66 49 [2] 21 58 [2] 6f 54 [2] 63 5e [2] 74 55 [2] 6f 1b [2] 52 }

  condition:
    any of them
}