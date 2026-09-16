rule TTP_XOR_MULT_DOSStub_2f3e {
  strings:
    $key_2f3e = { 7b 56 [2] 0f 4e [2] 48 4c [2] 0f 5d [2] 41 51 [2] 4d 5b [2] 5a 50 [2] 41 1e [2] 7c }

  condition:
    any of them
}