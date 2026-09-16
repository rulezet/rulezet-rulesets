rule TTP_XOR_MULT_DOSStub_6d30 {
  strings:
    $key_6d30 = { 39 58 [2] 4d 40 [2] 0a 42 [2] 4d 53 [2] 03 5f [2] 0f 55 [2] 18 5e [2] 03 10 [2] 3e }

  condition:
    any of them
}