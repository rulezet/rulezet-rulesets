rule TTP_XOR_MULT_DOSStub_0d2d {
  strings:
    $key_0d2d = { 59 45 [2] 2d 5d [2] 6a 5f [2] 2d 4e [2] 63 42 [2] 6f 48 [2] 78 43 [2] 63 0d [2] 5e }

  condition:
    any of them
}