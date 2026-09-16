rule TTP_XOR_MULT_DOSStub_556c {
  strings:
    $key_556c = { 01 04 [2] 75 1c [2] 32 1e [2] 75 0f [2] 3b 03 [2] 37 09 [2] 20 02 [2] 3b 4c [2] 06 }

  condition:
    any of them
}