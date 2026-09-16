rule TTP_XOR_MULT_DOSStub_681c {
  strings:
    $key_681c = { 3c 74 [2] 48 6c [2] 0f 6e [2] 48 7f [2] 06 73 [2] 0a 79 [2] 1d 72 [2] 06 3c [2] 3b }

  condition:
    any of them
}