rule TTP_XOR_MULT_DOSStub_f91d {
  strings:
    $key_f91d = { ad 75 [2] d9 6d [2] 9e 6f [2] d9 7e [2] 97 72 [2] 9b 78 [2] 8c 73 [2] 97 3d [2] aa }

  condition:
    any of them
}