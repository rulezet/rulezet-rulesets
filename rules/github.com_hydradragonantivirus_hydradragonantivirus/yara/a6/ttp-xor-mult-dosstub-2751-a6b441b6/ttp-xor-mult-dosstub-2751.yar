rule TTP_XOR_MULT_DOSStub_2751 {
  strings:
    $key_2751 = { 73 39 [2] 07 21 [2] 40 23 [2] 07 32 [2] 49 3e [2] 45 34 [2] 52 3f [2] 49 71 [2] 74 }

  condition:
    any of them
}