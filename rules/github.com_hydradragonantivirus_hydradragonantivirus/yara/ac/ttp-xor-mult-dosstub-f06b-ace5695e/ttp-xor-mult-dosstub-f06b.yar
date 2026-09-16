rule TTP_XOR_MULT_DOSStub_f06b {
  strings:
    $key_f06b = { a4 03 [2] d0 1b [2] 97 19 [2] d0 08 [2] 9e 04 [2] 92 0e [2] 85 05 [2] 9e 4b [2] a3 }

  condition:
    any of them
}