rule TTP_XOR_MULT_DOSStub_0766 {
  strings:
    $key_0766 = { 53 0e [2] 27 16 [2] 60 14 [2] 27 05 [2] 69 09 [2] 65 03 [2] 72 08 [2] 69 46 [2] 54 }

  condition:
    any of them
}