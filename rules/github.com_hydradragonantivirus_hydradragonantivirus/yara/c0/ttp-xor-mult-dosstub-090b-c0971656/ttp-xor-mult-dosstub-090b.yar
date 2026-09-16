rule TTP_XOR_MULT_DOSStub_090b {
  strings:
    $key_090b = { 5d 63 [2] 29 7b [2] 6e 79 [2] 29 68 [2] 67 64 [2] 6b 6e [2] 7c 65 [2] 67 2b [2] 5a }

  condition:
    any of them
}