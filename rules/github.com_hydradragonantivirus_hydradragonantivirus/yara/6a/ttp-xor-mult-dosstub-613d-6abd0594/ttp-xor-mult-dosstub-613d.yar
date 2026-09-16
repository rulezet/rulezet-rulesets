rule TTP_XOR_MULT_DOSStub_613d {
  strings:
    $key_613d = { 35 55 [2] 41 4d [2] 06 4f [2] 41 5e [2] 0f 52 [2] 03 58 [2] 14 53 [2] 0f 1d [2] 32 }

  condition:
    any of them
}