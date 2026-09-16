rule TTP_XOR_MULT_DOSStub_f91f {
  strings:
    $key_f91f = { ad 77 [2] d9 6f [2] 9e 6d [2] d9 7c [2] 97 70 [2] 9b 7a [2] 8c 71 [2] 97 3f [2] aa }

  condition:
    any of them
}