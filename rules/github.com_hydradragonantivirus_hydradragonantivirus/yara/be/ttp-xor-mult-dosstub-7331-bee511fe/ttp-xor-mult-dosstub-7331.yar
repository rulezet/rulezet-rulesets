rule TTP_XOR_MULT_DOSStub_7331 {
  strings:
    $key_7331 = { 27 59 [2] 53 41 [2] 14 43 [2] 53 52 [2] 1d 5e [2] 11 54 [2] 06 5f [2] 1d 11 [2] 20 }

  condition:
    any of them
}