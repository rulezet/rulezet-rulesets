rule TTP_XOR_MULT_DOSStub_f26c {
  strings:
    $key_f26c = { a6 04 [2] d2 1c [2] 95 1e [2] d2 0f [2] 9c 03 [2] 90 09 [2] 87 02 [2] 9c 4c [2] a1 }

  condition:
    any of them
}