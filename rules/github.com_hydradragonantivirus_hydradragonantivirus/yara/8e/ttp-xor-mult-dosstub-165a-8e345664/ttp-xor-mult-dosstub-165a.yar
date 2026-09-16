rule TTP_XOR_MULT_DOSStub_165a {
  strings:
    $key_165a = { 42 32 [2] 36 2a [2] 71 28 [2] 36 39 [2] 78 35 [2] 74 3f [2] 63 34 [2] 78 7a [2] 45 }

  condition:
    any of them
}