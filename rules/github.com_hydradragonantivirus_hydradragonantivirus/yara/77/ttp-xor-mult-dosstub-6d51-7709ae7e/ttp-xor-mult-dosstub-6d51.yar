rule TTP_XOR_MULT_DOSStub_6d51 {
  strings:
    $key_6d51 = { 39 39 [2] 4d 21 [2] 0a 23 [2] 4d 32 [2] 03 3e [2] 0f 34 [2] 18 3f [2] 03 71 [2] 3e }

  condition:
    any of them
}