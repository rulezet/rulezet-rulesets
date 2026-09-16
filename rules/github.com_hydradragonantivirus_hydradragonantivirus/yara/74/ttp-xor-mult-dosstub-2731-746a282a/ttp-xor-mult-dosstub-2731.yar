rule TTP_XOR_MULT_DOSStub_2731 {
  strings:
    $key_2731 = { 73 59 [2] 07 41 [2] 40 43 [2] 07 52 [2] 49 5e [2] 45 54 [2] 52 5f [2] 49 11 [2] 74 }

  condition:
    any of them
}