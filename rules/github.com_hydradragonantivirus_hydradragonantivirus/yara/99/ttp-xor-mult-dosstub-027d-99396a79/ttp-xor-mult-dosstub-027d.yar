rule TTP_XOR_MULT_DOSStub_027d {
  strings:
    $key_027d = { 56 15 [2] 22 0d [2] 65 0f [2] 22 1e [2] 6c 12 [2] 60 18 [2] 77 13 [2] 6c 5d [2] 51 }

  condition:
    any of them
}