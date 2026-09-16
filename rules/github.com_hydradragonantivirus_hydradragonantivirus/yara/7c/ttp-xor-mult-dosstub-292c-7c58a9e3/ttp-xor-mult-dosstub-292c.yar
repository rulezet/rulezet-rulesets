rule TTP_XOR_MULT_DOSStub_292c {
  strings:
    $key_292c = { 7d 44 [2] 09 5c [2] 4e 5e [2] 09 4f [2] 47 43 [2] 4b 49 [2] 5c 42 [2] 47 0c [2] 7a }

  condition:
    any of them
}