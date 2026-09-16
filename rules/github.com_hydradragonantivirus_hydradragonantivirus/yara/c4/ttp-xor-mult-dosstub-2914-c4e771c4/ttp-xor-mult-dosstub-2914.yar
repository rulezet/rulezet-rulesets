rule TTP_XOR_MULT_DOSStub_2914 {
  strings:
    $key_2914 = { 7d 7c [2] 09 64 [2] 4e 66 [2] 09 77 [2] 47 7b [2] 4b 71 [2] 5c 7a [2] 47 34 [2] 7a }

  condition:
    any of them
}