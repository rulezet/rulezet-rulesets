rule TTP_XOR_MULT_DOSStub_72fc {
  strings:
    $key_72fc = { 26 94 [2] 52 8c [2] 15 8e [2] 52 9f [2] 1c 93 [2] 10 99 [2] 07 92 [2] 1c dc [2] 21 }

  condition:
    any of them
}