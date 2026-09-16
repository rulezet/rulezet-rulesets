rule TTP_XOR_MULT_DOSStub_e33d {
  strings:
    $key_e33d = { b7 55 [2] c3 4d [2] 84 4f [2] c3 5e [2] 8d 52 [2] 81 58 [2] 96 53 [2] 8d 1d [2] b0 }

  condition:
    any of them
}