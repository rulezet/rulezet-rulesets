rule TTP_XOR_MULT_DOSStub_663d {
  strings:
    $key_663d = { 32 55 [2] 46 4d [2] 01 4f [2] 46 5e [2] 08 52 [2] 04 58 [2] 13 53 [2] 08 1d [2] 35 }

  condition:
    any of them
}