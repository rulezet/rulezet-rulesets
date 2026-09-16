rule TTP_XOR_MULT_DOSStub_2919 {
  strings:
    $key_2919 = { 7d 71 [2] 09 69 [2] 4e 6b [2] 09 7a [2] 47 76 [2] 4b 7c [2] 5c 77 [2] 47 39 [2] 7a }

  condition:
    any of them
}