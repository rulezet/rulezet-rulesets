rule TTP_XOR_MULT_DOSStub_372c {
  strings:
    $key_372c = { 63 44 [2] 17 5c [2] 50 5e [2] 17 4f [2] 59 43 [2] 55 49 [2] 42 42 [2] 59 0c [2] 64 }

  condition:
    any of them
}