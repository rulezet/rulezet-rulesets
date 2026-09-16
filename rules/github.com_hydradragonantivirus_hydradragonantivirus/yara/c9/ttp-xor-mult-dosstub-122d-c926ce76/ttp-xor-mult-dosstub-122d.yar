rule TTP_XOR_MULT_DOSStub_122d {
  strings:
    $key_122d = { 46 45 [2] 32 5d [2] 75 5f [2] 32 4e [2] 7c 42 [2] 70 48 [2] 67 43 [2] 7c 0d [2] 41 }

  condition:
    any of them
}