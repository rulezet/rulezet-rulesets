rule TTP_XOR_MULT_DOSStub_f9ea {
  strings:
    $key_f9ea = { ad 82 [2] d9 9a [2] 9e 98 [2] d9 89 [2] 97 85 [2] 9b 8f [2] 8c 84 [2] 97 ca [2] aa }

  condition:
    any of them
}