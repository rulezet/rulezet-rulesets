rule TTP_XOR_MULT_DOSStub_180b {
  strings:
    $key_180b = { 4c 63 [2] 38 7b [2] 7f 79 [2] 38 68 [2] 76 64 [2] 7a 6e [2] 6d 65 [2] 76 2b [2] 4b }

  condition:
    any of them
}