rule TTP_XOR_MULT_DOSStub_362c {
  strings:
    $key_362c = { 62 44 [2] 16 5c [2] 51 5e [2] 16 4f [2] 58 43 [2] 54 49 [2] 43 42 [2] 58 0c [2] 65 }

  condition:
    any of them
}