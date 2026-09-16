rule TTP_XOR_MULT_DOSStub_290b {
  strings:
    $key_290b = { 7d 63 [2] 09 7b [2] 4e 79 [2] 09 68 [2] 47 64 [2] 4b 6e [2] 5c 65 [2] 47 2b [2] 7a }

  condition:
    any of them
}