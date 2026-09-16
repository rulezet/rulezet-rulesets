rule TTP_XOR_MULT_DOSStub_2939 {
  strings:
    $key_2939 = { 7d 51 [2] 09 49 [2] 4e 4b [2] 09 5a [2] 47 56 [2] 4b 5c [2] 5c 57 [2] 47 19 [2] 7a }

  condition:
    any of them
}