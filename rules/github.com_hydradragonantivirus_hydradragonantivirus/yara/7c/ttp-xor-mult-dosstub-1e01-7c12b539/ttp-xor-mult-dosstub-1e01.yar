rule TTP_XOR_MULT_DOSStub_1e01 {
  strings:
    $key_1e01 = { 4a 69 [2] 3e 71 [2] 79 73 [2] 3e 62 [2] 70 6e [2] 7c 64 [2] 6b 6f [2] 70 21 [2] 4d }

  condition:
    any of them
}