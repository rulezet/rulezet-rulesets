rule TTP_XOR_MULT_DOSStub_2964 {
  strings:
    $key_2964 = { 7d 0c [2] 09 14 [2] 4e 16 [2] 09 07 [2] 47 0b [2] 4b 01 [2] 5c 0a [2] 47 44 [2] 7a }

  condition:
    any of them
}