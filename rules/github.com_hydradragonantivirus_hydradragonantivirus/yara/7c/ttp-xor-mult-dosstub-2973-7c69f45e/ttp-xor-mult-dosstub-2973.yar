rule TTP_XOR_MULT_DOSStub_2973 {
  strings:
    $key_2973 = { 7d 1b [2] 09 03 [2] 4e 01 [2] 09 10 [2] 47 1c [2] 4b 16 [2] 5c 1d [2] 47 53 [2] 7a }

  condition:
    any of them
}