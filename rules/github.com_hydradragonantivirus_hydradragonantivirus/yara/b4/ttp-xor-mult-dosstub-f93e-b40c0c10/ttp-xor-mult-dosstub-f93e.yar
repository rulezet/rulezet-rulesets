rule TTP_XOR_MULT_DOSStub_f93e {
  strings:
    $key_f93e = { ad 56 [2] d9 4e [2] 9e 4c [2] d9 5d [2] 97 51 [2] 9b 5b [2] 8c 50 [2] 97 1e [2] aa }

  condition:
    any of them
}