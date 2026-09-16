rule TTP_XOR_MULT_DOSStub_614c {
  strings:
    $key_614c = { 35 24 [2] 41 3c [2] 06 3e [2] 41 2f [2] 0f 23 [2] 03 29 [2] 14 22 [2] 0f 6c [2] 32 }

  condition:
    any of them
}