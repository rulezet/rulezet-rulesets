rule TTP_XOR_MULT_DOSStub_2be1 {
  strings:
    $key_2be1 = { 7f 89 [2] 0b 91 [2] 4c 93 [2] 0b 82 [2] 45 8e [2] 49 84 [2] 5e 8f [2] 45 c1 [2] 78 }

  condition:
    any of them
}