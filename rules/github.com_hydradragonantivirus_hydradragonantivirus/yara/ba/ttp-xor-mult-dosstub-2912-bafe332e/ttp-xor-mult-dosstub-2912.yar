rule TTP_XOR_MULT_DOSStub_2912 {
  strings:
    $key_2912 = { 7d 7a [2] 09 62 [2] 4e 60 [2] 09 71 [2] 47 7d [2] 4b 77 [2] 5c 7c [2] 47 32 [2] 7a }

  condition:
    any of them
}