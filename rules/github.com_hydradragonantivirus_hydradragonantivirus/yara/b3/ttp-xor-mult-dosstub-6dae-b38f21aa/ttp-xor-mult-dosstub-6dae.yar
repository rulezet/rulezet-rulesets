rule TTP_XOR_MULT_DOSStub_6dae {
  strings:
    $key_6dae = { 39 c6 [2] 4d de [2] 0a dc [2] 4d cd [2] 03 c1 [2] 0f cb [2] 18 c0 [2] 03 8e [2] 3e }

  condition:
    any of them
}