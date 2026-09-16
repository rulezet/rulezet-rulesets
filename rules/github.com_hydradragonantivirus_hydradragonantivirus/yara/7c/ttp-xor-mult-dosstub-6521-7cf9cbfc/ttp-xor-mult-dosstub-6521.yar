rule TTP_XOR_MULT_DOSStub_6521 {
  strings:
    $key_6521 = { 31 49 [2] 45 51 [2] 02 53 [2] 45 42 [2] 0b 4e [2] 07 44 [2] 10 4f [2] 0b 01 [2] 36 }

  condition:
    any of them
}