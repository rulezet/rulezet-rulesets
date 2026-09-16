rule TTP_XOR_MULT_DOSStub_2933 {
  strings:
    $key_2933 = { 7d 5b [2] 09 43 [2] 4e 41 [2] 09 50 [2] 47 5c [2] 4b 56 [2] 5c 5d [2] 47 13 [2] 7a }

  condition:
    any of them
}