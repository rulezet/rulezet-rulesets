rule TTP_XOR_MULT_DOSStub_064c {
  strings:
    $key_064c = { 52 24 [2] 26 3c [2] 61 3e [2] 26 2f [2] 68 23 [2] 64 29 [2] 73 22 [2] 68 6c [2] 55 }

  condition:
    any of them
}