rule TTP_XOR_MULT_DOSStub_2770 {
  strings:
    $key_2770 = { 73 18 [2] 07 00 [2] 40 02 [2] 07 13 [2] 49 1f [2] 45 15 [2] 52 1e [2] 49 50 [2] 74 }

  condition:
    any of them
}