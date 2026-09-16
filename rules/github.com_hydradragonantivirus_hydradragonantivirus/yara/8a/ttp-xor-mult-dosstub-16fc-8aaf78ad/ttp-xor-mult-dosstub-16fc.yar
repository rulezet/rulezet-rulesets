rule TTP_XOR_MULT_DOSStub_16fc {
  strings:
    $key_16fc = { 42 94 [2] 36 8c [2] 71 8e [2] 36 9f [2] 78 93 [2] 74 99 [2] 63 92 [2] 78 dc [2] 45 }

  condition:
    any of them
}