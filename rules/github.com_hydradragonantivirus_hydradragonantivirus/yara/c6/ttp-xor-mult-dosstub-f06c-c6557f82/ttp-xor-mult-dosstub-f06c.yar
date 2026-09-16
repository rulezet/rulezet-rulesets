rule TTP_XOR_MULT_DOSStub_f06c {
  strings:
    $key_f06c = { a4 04 [2] d0 1c [2] 97 1e [2] d0 0f [2] 9e 03 [2] 92 09 [2] 85 02 [2] 9e 4c [2] a3 }

  condition:
    any of them
}