rule TTP_XOR_MULT_DOSStub_2903 {
  strings:
    $key_2903 = { 7d 6b [2] 09 73 [2] 4e 71 [2] 09 60 [2] 47 6c [2] 4b 66 [2] 5c 6d [2] 47 23 [2] 7a }

  condition:
    any of them
}