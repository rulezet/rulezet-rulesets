rule TTP_XOR_MULT_DOSStub_f9ba {
  strings:
    $key_f9ba = { ad d2 [2] d9 ca [2] 9e c8 [2] d9 d9 [2] 97 d5 [2] 9b df [2] 8c d4 [2] 97 9a [2] aa }

  condition:
    any of them
}