rule TTP_XOR_MULT_DOSStub_322c {
  strings:
    $key_322c = { 66 44 [2] 12 5c [2] 55 5e [2] 12 4f [2] 5c 43 [2] 50 49 [2] 47 42 [2] 5c 0c [2] 61 }

  condition:
    any of them
}