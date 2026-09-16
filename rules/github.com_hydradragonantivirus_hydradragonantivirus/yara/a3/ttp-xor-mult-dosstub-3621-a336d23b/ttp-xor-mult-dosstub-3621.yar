rule TTP_XOR_MULT_DOSStub_3621 {
  strings:
    $key_3621 = { 62 49 [2] 16 51 [2] 51 53 [2] 16 42 [2] 58 4e [2] 54 44 [2] 43 4f [2] 58 01 [2] 65 }

  condition:
    any of them
}