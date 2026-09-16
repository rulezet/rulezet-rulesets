rule TTP_XOR_MULT_DOSStub_f71d {
  strings:
    $key_f71d = { a3 75 [2] d7 6d [2] 90 6f [2] d7 7e [2] 99 72 [2] 95 78 [2] 82 73 [2] 99 3d [2] a4 }

  condition:
    any of them
}