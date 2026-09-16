rule TTP_XOR_MULT_DOSStub_f939 {
  strings:
    $key_f939 = { ad 51 [2] d9 49 [2] 9e 4b [2] d9 5a [2] 97 56 [2] 9b 5c [2] 8c 57 [2] 97 19 [2] aa }

  condition:
    any of them
}