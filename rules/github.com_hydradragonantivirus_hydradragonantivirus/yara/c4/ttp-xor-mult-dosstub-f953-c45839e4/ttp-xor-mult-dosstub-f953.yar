rule TTP_XOR_MULT_DOSStub_f953 {
  strings:
    $key_f953 = { ad 3b [2] d9 23 [2] 9e 21 [2] d9 30 [2] 97 3c [2] 9b 36 [2] 8c 3d [2] 97 73 [2] aa }

  condition:
    any of them
}