rule TTP_XOR_MULT_DOSStub_2943 {
  strings:
    $key_2943 = { 7d 2b [2] 09 33 [2] 4e 31 [2] 09 20 [2] 47 2c [2] 4b 26 [2] 5c 2d [2] 47 63 [2] 7a }

  condition:
    any of them
}