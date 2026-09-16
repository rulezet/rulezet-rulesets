rule TTP_XOR_MULT_DOSStub_6a30 {
  strings:
    $key_6a30 = { 3e 58 [2] 4a 40 [2] 0d 42 [2] 4a 53 [2] 04 5f [2] 08 55 [2] 1f 5e [2] 04 10 [2] 39 }

  condition:
    any of them
}