rule TTP_XOR_MULT_DOSStub_f660 {
  strings:
    $key_f660 = { a2 08 [2] d6 10 [2] 91 12 [2] d6 03 [2] 98 0f [2] 94 05 [2] 83 0e [2] 98 40 [2] a5 }

  condition:
    any of them
}