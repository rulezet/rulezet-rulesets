rule TTP_XOR_MULT_DOSStub_e46d {
  strings:
    $key_e46d = { b0 05 [2] c4 1d [2] 83 1f [2] c4 0e [2] 8a 02 [2] 86 08 [2] 91 03 [2] 8a 4d [2] b7 }

  condition:
    any of them
}