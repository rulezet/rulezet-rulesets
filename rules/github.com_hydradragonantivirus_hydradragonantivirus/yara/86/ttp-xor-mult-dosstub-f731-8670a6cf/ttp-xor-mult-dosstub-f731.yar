rule TTP_XOR_MULT_DOSStub_f731 {
  strings:
    $key_f731 = { a3 59 [2] d7 41 [2] 90 43 [2] d7 52 [2] 99 5e [2] 95 54 [2] 82 5f [2] 99 11 [2] a4 }

  condition:
    any of them
}