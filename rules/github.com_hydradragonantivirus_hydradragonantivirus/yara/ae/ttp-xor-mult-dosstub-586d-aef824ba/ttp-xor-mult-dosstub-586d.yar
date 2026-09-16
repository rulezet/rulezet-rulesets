rule TTP_XOR_MULT_DOSStub_586d {
  strings:
    $key_586d = { 0c 05 [2] 78 1d [2] 3f 1f [2] 78 0e [2] 36 02 [2] 3a 08 [2] 2d 03 [2] 36 4d [2] 0b }

  condition:
    any of them
}