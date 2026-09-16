rule TTP_XOR_MULT_DOSStub_253b {
  strings:
    $key_253b = { 71 53 [2] 05 4b [2] 42 49 [2] 05 58 [2] 4b 54 [2] 47 5e [2] 50 55 [2] 4b 1b [2] 76 }

  condition:
    any of them
}