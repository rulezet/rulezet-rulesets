rule TTP_XOR_MULT_DOSStub_3471 {
  strings:
    $key_3471 = { 60 19 [2] 14 01 [2] 53 03 [2] 14 12 [2] 5a 1e [2] 56 14 [2] 41 1f [2] 5a 51 [2] 67 }

  condition:
    any of them
}