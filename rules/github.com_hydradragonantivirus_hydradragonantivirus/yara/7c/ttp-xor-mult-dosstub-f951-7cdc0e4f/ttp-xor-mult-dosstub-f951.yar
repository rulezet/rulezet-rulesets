rule TTP_XOR_MULT_DOSStub_f951 {
  strings:
    $key_f951 = { ad 39 [2] d9 21 [2] 9e 23 [2] d9 32 [2] 97 3e [2] 9b 34 [2] 8c 3f [2] 97 71 [2] aa }

  condition:
    any of them
}