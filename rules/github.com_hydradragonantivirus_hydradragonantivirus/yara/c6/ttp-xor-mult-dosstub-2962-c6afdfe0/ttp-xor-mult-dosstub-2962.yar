rule TTP_XOR_MULT_DOSStub_2962 {
  strings:
    $key_2962 = { 7d 0a [2] 09 12 [2] 4e 10 [2] 09 01 [2] 47 0d [2] 4b 07 [2] 5c 0c [2] 47 42 [2] 7a }

  condition:
    any of them
}