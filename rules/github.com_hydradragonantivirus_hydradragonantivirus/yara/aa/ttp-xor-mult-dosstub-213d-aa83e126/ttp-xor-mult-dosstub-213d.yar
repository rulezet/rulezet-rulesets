rule TTP_XOR_MULT_DOSStub_213d {
  strings:
    $key_213d = { 75 55 [2] 01 4d [2] 46 4f [2] 01 5e [2] 4f 52 [2] 43 58 [2] 54 53 [2] 4f 1d [2] 72 }

  condition:
    any of them
}