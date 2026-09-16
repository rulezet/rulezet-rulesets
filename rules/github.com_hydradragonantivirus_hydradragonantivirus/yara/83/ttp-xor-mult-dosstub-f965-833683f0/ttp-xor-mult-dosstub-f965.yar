rule TTP_XOR_MULT_DOSStub_f965 {
  strings:
    $key_f965 = { ad 0d [2] d9 15 [2] 9e 17 [2] d9 06 [2] 97 0a [2] 9b 00 [2] 8c 0b [2] 97 45 [2] aa }

  condition:
    any of them
}