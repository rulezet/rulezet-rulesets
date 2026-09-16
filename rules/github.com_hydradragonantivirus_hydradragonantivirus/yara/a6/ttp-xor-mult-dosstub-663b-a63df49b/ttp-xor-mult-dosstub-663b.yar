rule TTP_XOR_MULT_DOSStub_663b {
  strings:
    $key_663b = { 32 53 [2] 46 4b [2] 01 49 [2] 46 58 [2] 08 54 [2] 04 5e [2] 13 55 [2] 08 1b [2] 35 }

  condition:
    any of them
}