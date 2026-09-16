rule TTP_XOR_MULT_DOSStub_3f2d {
  strings:
    $key_3f2d = { 6b 45 [2] 1f 5d [2] 58 5f [2] 1f 4e [2] 51 42 [2] 5d 48 [2] 4a 43 [2] 51 0d [2] 6c }

  condition:
    any of them
}