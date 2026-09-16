rule TTP_XOR_MULT_DOSStub_2706 {
  strings:
    $key_2706 = { 73 6e [2] 07 76 [2] 40 74 [2] 07 65 [2] 49 69 [2] 45 63 [2] 52 68 [2] 49 26 [2] 74 }

  condition:
    any of them
}