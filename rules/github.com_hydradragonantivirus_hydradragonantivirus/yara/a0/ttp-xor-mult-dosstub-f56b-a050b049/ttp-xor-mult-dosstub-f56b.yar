rule TTP_XOR_MULT_DOSStub_f56b {
  strings:
    $key_f56b = { a1 03 [2] d5 1b [2] 92 19 [2] d5 08 [2] 9b 04 [2] 97 0e [2] 80 05 [2] 9b 4b [2] a6 }

  condition:
    any of them
}