rule TTP_XOR_MULT_DOSStub_f919 {
  strings:
    $key_f919 = { ad 71 [2] d9 69 [2] 9e 6b [2] d9 7a [2] 97 76 [2] 9b 7c [2] 8c 77 [2] 97 39 [2] aa }

  condition:
    any of them
}