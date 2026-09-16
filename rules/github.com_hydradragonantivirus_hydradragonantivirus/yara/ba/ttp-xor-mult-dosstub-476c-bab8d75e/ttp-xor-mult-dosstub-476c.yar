rule TTP_XOR_MULT_DOSStub_476c {
  strings:
    $key_476c = { 13 04 [2] 67 1c [2] 20 1e [2] 67 0f [2] 29 03 [2] 25 09 [2] 32 02 [2] 29 4c [2] 14 }

  condition:
    any of them
}