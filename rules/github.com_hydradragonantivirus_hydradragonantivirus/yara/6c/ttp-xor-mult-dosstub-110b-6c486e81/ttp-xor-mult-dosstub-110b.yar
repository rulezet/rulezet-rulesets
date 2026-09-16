rule TTP_XOR_MULT_DOSStub_110b {
  strings:
    $key_110b = { 45 63 [2] 31 7b [2] 76 79 [2] 31 68 [2] 7f 64 [2] 73 6e [2] 64 65 [2] 7f 2b [2] 42 }

  condition:
    any of them
}