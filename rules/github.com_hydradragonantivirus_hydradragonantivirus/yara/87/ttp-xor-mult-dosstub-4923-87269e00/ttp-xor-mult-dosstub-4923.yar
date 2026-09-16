rule TTP_XOR_MULT_DOSStub_4923 {
  strings:
    $key_4923 = { 1d 4b [2] 69 53 [2] 2e 51 [2] 69 40 [2] 27 4c [2] 2b 46 [2] 3c 4d [2] 27 03 [2] 1a }

  condition:
    any of them
}