rule TTP_XOR_MULT_DOSStub_2935 {
  strings:
    $key_2935 = { 7d 5d [2] 09 45 [2] 4e 47 [2] 09 56 [2] 47 5a [2] 4b 50 [2] 5c 5b [2] 47 15 [2] 7a }

  condition:
    any of them
}