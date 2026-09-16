rule TTP_XOR_MULT_DOSStub_0f3d {
  strings:
    $key_0f3d = { 5b 55 [2] 2f 4d [2] 68 4f [2] 2f 5e [2] 61 52 [2] 6d 58 [2] 7a 53 [2] 61 1d [2] 5c }

  condition:
    any of them
}