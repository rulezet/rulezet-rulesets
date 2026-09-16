rule TTP_XOR_MULT_DOSStub_f979 {
  strings:
    $key_f979 = { ad 11 [2] d9 09 [2] 9e 0b [2] d9 1a [2] 97 16 [2] 9b 1c [2] 8c 17 [2] 97 59 [2] aa }

  condition:
    any of them
}