rule TTP_XOR_MULT_DOSStub_7e01 {
  strings:
    $key_7e01 = { 2a 69 [2] 5e 71 [2] 19 73 [2] 5e 62 [2] 10 6e [2] 1c 64 [2] 0b 6f [2] 10 21 [2] 2d }

  condition:
    any of them
}