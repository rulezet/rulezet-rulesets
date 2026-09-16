rule TTP_XOR_MULT_DOSStub_2721 {
  strings:
    $key_2721 = { 73 49 [2] 07 51 [2] 40 53 [2] 07 42 [2] 49 4e [2] 45 44 [2] 52 4f [2] 49 01 [2] 74 }

  condition:
    any of them
}