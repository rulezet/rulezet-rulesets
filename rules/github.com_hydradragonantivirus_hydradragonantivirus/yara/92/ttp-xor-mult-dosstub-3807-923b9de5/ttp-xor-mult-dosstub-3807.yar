rule TTP_XOR_MULT_DOSStub_3807 {
  strings:
    $key_3807 = { 6c 6f [2] 18 77 [2] 5f 75 [2] 18 64 [2] 56 68 [2] 5a 62 [2] 4d 69 [2] 56 27 [2] 6b }

  condition:
    any of them
}