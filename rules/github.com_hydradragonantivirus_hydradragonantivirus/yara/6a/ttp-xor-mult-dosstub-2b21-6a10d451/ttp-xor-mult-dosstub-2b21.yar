rule TTP_XOR_MULT_DOSStub_2b21 {
  strings:
    $key_2b21 = { 7f 49 [2] 0b 51 [2] 4c 53 [2] 0b 42 [2] 45 4e [2] 49 44 [2] 5e 4f [2] 45 01 [2] 78 }

  condition:
    any of them
}