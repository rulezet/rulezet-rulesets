rule TTP_XOR_MULT_DOSStub_376c {
  strings:
    $key_376c = { 63 04 [2] 17 1c [2] 50 1e [2] 17 0f [2] 59 03 [2] 55 09 [2] 42 02 [2] 59 4c [2] 64 }

  condition:
    any of them
}