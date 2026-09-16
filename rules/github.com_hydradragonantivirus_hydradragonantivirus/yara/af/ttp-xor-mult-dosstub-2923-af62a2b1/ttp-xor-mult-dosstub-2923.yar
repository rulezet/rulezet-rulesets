rule TTP_XOR_MULT_DOSStub_2923 {
  strings:
    $key_2923 = { 7d 4b [2] 09 53 [2] 4e 51 [2] 09 40 [2] 47 4c [2] 4b 46 [2] 5c 4d [2] 47 03 [2] 7a }

  condition:
    any of them
}