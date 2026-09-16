rule TTP_XOR_MULT_DOSStub_292d {
  strings:
    $key_292d = { 7d 45 [2] 09 5d [2] 4e 5f [2] 09 4e [2] 47 42 [2] 4b 48 [2] 5c 43 [2] 47 0d [2] 7a }

  condition:
    any of them
}