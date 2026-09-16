rule TTP_XOR_MULT_DOSStub_6a77 {
  strings:
    $key_6a77 = { 3e 1f [2] 4a 07 [2] 0d 05 [2] 4a 14 [2] 04 18 [2] 08 12 [2] 1f 19 [2] 04 57 [2] 39 }

  condition:
    any of them
}