rule TTP_XOR_MULT_DOSStub_2968 {
  strings:
    $key_2968 = { 7d 00 [2] 09 18 [2] 4e 1a [2] 09 0b [2] 47 07 [2] 4b 0d [2] 5c 06 [2] 47 48 [2] 7a }

  condition:
    any of them
}