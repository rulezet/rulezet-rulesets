rule TTP_XOR_MULT_DOSStub_5fe0 {
  strings:
    $key_5fe0 = { 0b 88 [2] 7f 90 [2] 38 92 [2] 7f 83 [2] 31 8f [2] 3d 85 [2] 2a 8e [2] 31 c0 [2] 0c }

  condition:
    any of them
}