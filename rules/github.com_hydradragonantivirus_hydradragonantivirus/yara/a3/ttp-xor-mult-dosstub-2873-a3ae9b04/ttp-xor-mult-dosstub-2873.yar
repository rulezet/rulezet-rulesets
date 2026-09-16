rule TTP_XOR_MULT_DOSStub_2873 {
  strings:
    $key_2873 = { 7c 1b [2] 08 03 [2] 4f 01 [2] 08 10 [2] 46 1c [2] 4a 16 [2] 5d 1d [2] 46 53 [2] 7b }

  condition:
    any of them
}