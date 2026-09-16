rule TTP_XOR_MULT_DOSStub_d807 {
  strings:
    $key_d807 = { 8c 6f [2] f8 77 [2] bf 75 [2] f8 64 [2] b6 68 [2] ba 62 [2] ad 69 [2] b6 27 [2] 8b }

  condition:
    any of them
}