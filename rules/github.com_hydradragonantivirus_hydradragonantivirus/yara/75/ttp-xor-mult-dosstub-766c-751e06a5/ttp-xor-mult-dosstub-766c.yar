rule TTP_XOR_MULT_DOSStub_766c {
  strings:
    $key_766c = { 22 04 [2] 56 1c [2] 11 1e [2] 56 0f [2] 18 03 [2] 14 09 [2] 03 02 [2] 18 4c [2] 25 }

  condition:
    any of them
}