rule TTP_XOR_MULT_DOSStub_e827 {
  strings:
    $key_e827 = { bc 4f [2] c8 57 [2] 8f 55 [2] c8 44 [2] 86 48 [2] 8a 42 [2] 9d 49 [2] 86 07 [2] bb }

  condition:
    any of them
}