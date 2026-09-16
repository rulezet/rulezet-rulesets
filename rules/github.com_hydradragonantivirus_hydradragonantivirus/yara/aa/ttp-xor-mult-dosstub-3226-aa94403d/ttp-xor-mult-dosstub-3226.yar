rule TTP_XOR_MULT_DOSStub_3226 {
  strings:
    $key_3226 = { 66 4e [2] 12 56 [2] 55 54 [2] 12 45 [2] 5c 49 [2] 50 43 [2] 47 48 [2] 5c 06 [2] 61 }

  condition:
    any of them
}