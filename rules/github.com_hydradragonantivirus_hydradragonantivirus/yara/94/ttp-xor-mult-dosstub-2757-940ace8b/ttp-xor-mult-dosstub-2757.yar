rule TTP_XOR_MULT_DOSStub_2757 {
  strings:
    $key_2757 = { 73 3f [2] 07 27 [2] 40 25 [2] 07 34 [2] 49 38 [2] 45 32 [2] 52 39 [2] 49 77 [2] 74 }

  condition:
    any of them
}