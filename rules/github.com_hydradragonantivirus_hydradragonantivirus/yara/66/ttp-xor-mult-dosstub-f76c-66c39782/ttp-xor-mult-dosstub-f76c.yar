rule TTP_XOR_MULT_DOSStub_f76c {
  strings:
    $key_f76c = { a3 04 [2] d7 1c [2] 90 1e [2] d7 0f [2] 99 03 [2] 95 09 [2] 82 02 [2] 99 4c [2] a4 }

  condition:
    any of them
}