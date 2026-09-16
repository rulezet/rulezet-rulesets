rule TTP_XOR_MULT_DOSStub_f93c {
  strings:
    $key_f93c = { ad 54 [2] d9 4c [2] 9e 4e [2] d9 5f [2] 97 53 [2] 9b 59 [2] 8c 52 [2] 97 1c [2] aa }

  condition:
    any of them
}