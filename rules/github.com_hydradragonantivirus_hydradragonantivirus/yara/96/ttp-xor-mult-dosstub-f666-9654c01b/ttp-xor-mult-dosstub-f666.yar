rule TTP_XOR_MULT_DOSStub_f666 {
  strings:
    $key_f666 = { a2 0e [2] d6 16 [2] 91 14 [2] d6 05 [2] 98 09 [2] 94 03 [2] 83 08 [2] 98 46 [2] a5 }

  condition:
    any of them
}