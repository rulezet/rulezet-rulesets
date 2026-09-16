rule TTP_XOR_MULT_DOSStub_6af6 {
  strings:
    $key_6af6 = { 3e 9e [2] 4a 86 [2] 0d 84 [2] 4a 95 [2] 04 99 [2] 08 93 [2] 1f 98 [2] 04 d6 [2] 39 }

  condition:
    any of them
}