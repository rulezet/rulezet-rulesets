rule TTP_XOR_MULT_DOSStub_f964 {
  strings:
    $key_f964 = { ad 0c [2] d9 14 [2] 9e 16 [2] d9 07 [2] 97 0b [2] 9b 01 [2] 8c 0a [2] 97 44 [2] aa }

  condition:
    any of them
}