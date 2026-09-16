rule TTP_XOR_MULT_DOSStub_f924 {
  strings:
    $key_f924 = { ad 4c [2] d9 54 [2] 9e 56 [2] d9 47 [2] 97 4b [2] 9b 41 [2] 8c 4a [2] 97 04 [2] aa }

  condition:
    any of them
}