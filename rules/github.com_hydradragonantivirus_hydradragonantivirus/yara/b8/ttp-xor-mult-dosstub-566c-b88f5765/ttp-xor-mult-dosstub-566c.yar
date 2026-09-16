rule TTP_XOR_MULT_DOSStub_566c {
  strings:
    $key_566c = { 02 04 [2] 76 1c [2] 31 1e [2] 76 0f [2] 38 03 [2] 34 09 [2] 23 02 [2] 38 4c [2] 05 }

  condition:
    any of them
}