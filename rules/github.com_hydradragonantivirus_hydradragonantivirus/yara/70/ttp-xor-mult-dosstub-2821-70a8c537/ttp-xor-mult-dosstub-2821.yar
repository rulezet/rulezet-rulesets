rule TTP_XOR_MULT_DOSStub_2821 {
  strings:
    $key_2821 = { 7c 49 [2] 08 51 [2] 4f 53 [2] 08 42 [2] 46 4e [2] 4a 44 [2] 5d 4f [2] 46 01 [2] 7b }

  condition:
    any of them
}