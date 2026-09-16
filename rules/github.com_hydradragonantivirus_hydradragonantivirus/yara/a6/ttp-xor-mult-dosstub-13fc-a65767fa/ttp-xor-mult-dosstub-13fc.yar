rule TTP_XOR_MULT_DOSStub_13fc {
  strings:
    $key_13fc = { 47 94 [2] 33 8c [2] 74 8e [2] 33 9f [2] 7d 93 [2] 71 99 [2] 66 92 [2] 7d dc [2] 40 }

  condition:
    any of them
}