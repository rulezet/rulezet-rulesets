rule TTP_XOR_MULT_DOSStub_e871 {
  strings:
    $key_e871 = { bc 19 [2] c8 01 [2] 8f 03 [2] c8 12 [2] 86 1e [2] 8a 14 [2] 9d 1f [2] 86 51 [2] bb }

  condition:
    any of them
}