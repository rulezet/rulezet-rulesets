rule TTP_XOR_MULT_DOSStub_e36d {
  strings:
    $key_e36d = { b7 05 [2] c3 1d [2] 84 1f [2] c3 0e [2] 8d 02 [2] 81 08 [2] 96 03 [2] 8d 4d [2] b0 }

  condition:
    any of them
}