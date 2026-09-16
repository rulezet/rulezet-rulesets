rule TTP_XOR_MULT_DOSStub_3b51 {
  strings:
    $key_3b51 = { 6f 39 [2] 1b 21 [2] 5c 23 [2] 1b 32 [2] 55 3e [2] 59 34 [2] 4e 3f [2] 55 71 [2] 68 }

  condition:
    any of them
}