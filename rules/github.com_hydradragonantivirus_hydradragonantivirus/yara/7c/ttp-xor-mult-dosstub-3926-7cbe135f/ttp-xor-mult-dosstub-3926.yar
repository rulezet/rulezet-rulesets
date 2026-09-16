rule TTP_XOR_MULT_DOSStub_3926 {
  strings:
    $key_3926 = { 6d 4e [2] 19 56 [2] 5e 54 [2] 19 45 [2] 57 49 [2] 5b 43 [2] 4c 48 [2] 57 06 [2] 6a }

  condition:
    any of them
}