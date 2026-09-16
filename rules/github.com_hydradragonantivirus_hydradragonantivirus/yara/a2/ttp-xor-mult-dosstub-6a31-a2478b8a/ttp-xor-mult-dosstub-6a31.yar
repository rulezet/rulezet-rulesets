rule TTP_XOR_MULT_DOSStub_6a31 {
  strings:
    $key_6a31 = { 3e 59 [2] 4a 41 [2] 0d 43 [2] 4a 52 [2] 04 5e [2] 08 54 [2] 1f 5f [2] 04 11 [2] 39 }

  condition:
    any of them
}