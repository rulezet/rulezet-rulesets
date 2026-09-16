rule TTP_XOR_MULT_DOSStub_2975 {
  strings:
    $key_2975 = { 7d 1d [2] 09 05 [2] 4e 07 [2] 09 16 [2] 47 1a [2] 4b 10 [2] 5c 1b [2] 47 55 [2] 7a }

  condition:
    any of them
}