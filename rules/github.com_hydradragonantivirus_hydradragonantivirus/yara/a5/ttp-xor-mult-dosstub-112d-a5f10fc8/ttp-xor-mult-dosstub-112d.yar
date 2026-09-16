rule TTP_XOR_MULT_DOSStub_112d {
  strings:
    $key_112d = { 45 45 [2] 31 5d [2] 76 5f [2] 31 4e [2] 7f 42 [2] 73 48 [2] 64 43 [2] 7f 0d [2] 42 }

  condition:
    any of them
}