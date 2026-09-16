rule TTP_XOR_MULT_DOSStub_2902 {
  strings:
    $key_2902 = { 7d 6a [2] 09 72 [2] 4e 70 [2] 09 61 [2] 47 6d [2] 4b 67 [2] 5c 6c [2] 47 22 [2] 7a }

  condition:
    any of them
}