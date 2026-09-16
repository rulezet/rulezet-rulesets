rule TTP_XOR_MULT_DOSStub_29fc {
  strings:
    $key_29fc = { 7d 94 [2] 09 8c [2] 4e 8e [2] 09 9f [2] 47 93 [2] 4b 99 [2] 5c 92 [2] 47 dc [2] 7a }

  condition:
    any of them
}