rule TTP_XOR_MULT_DOSStub_292a {
  strings:
    $key_292a = { 7d 42 [2] 09 5a [2] 4e 58 [2] 09 49 [2] 47 45 [2] 4b 4f [2] 5c 44 [2] 47 0a [2] 7a }

  condition:
    any of them
}