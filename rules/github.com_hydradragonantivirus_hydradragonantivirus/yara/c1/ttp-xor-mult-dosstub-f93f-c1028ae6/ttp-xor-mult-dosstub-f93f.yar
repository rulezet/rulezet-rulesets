rule TTP_XOR_MULT_DOSStub_f93f {
  strings:
    $key_f93f = { ad 57 [2] d9 4f [2] 9e 4d [2] d9 5c [2] 97 50 [2] 9b 5a [2] 8c 51 [2] 97 1f [2] aa }

  condition:
    any of them
}