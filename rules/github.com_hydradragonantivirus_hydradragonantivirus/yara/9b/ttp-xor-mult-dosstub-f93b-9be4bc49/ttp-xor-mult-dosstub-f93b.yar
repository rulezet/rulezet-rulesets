rule TTP_XOR_MULT_DOSStub_f93b {
  strings:
    $key_f93b = { ad 53 [2] d9 4b [2] 9e 49 [2] d9 58 [2] 97 54 [2] 9b 5e [2] 8c 55 [2] 97 1b [2] aa }

  condition:
    any of them
}