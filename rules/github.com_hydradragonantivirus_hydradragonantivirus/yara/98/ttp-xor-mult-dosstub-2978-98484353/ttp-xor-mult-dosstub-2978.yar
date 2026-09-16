rule TTP_XOR_MULT_DOSStub_2978 {
  strings:
    $key_2978 = { 7d 10 [2] 09 08 [2] 4e 0a [2] 09 1b [2] 47 17 [2] 4b 1d [2] 5c 16 [2] 47 58 [2] 7a }

  condition:
    any of them
}