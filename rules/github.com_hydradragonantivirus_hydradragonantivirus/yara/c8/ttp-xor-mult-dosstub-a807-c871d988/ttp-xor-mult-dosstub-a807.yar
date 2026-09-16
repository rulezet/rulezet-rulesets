rule TTP_XOR_MULT_DOSStub_a807 {
  strings:
    $key_a807 = { fc 6f [2] 88 77 [2] cf 75 [2] 88 64 [2] c6 68 [2] ca 62 [2] dd 69 [2] c6 27 [2] fb }

  condition:
    any of them
}