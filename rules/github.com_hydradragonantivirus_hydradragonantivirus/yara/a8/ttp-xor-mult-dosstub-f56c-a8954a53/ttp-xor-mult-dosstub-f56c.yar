rule TTP_XOR_MULT_DOSStub_f56c {
  strings:
    $key_f56c = { a1 04 [2] d5 1c [2] 92 1e [2] d5 0f [2] 9b 03 [2] 97 09 [2] 80 02 [2] 9b 4c [2] a6 }

  condition:
    any of them
}