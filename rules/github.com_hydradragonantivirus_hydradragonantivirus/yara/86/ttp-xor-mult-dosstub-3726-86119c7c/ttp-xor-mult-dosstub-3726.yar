rule TTP_XOR_MULT_DOSStub_3726 {
  strings:
    $key_3726 = { 63 4e [2] 17 56 [2] 50 54 [2] 17 45 [2] 59 49 [2] 55 43 [2] 42 48 [2] 59 06 [2] 64 }

  condition:
    any of them
}