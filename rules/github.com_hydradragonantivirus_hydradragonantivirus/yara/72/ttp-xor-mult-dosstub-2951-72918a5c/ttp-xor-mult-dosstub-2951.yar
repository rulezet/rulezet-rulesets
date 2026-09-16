rule TTP_XOR_MULT_DOSStub_2951 {
  strings:
    $key_2951 = { 7d 39 [2] 09 21 [2] 4e 23 [2] 09 32 [2] 47 3e [2] 4b 34 [2] 5c 3f [2] 47 71 [2] 7a }

  condition:
    any of them
}