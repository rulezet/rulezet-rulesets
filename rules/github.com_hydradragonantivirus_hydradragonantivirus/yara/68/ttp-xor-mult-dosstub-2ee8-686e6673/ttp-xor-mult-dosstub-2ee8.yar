rule TTP_XOR_MULT_DOSStub_2ee8 {
  strings:
    $key_2ee8 = { 7a 80 [2] 0e 98 [2] 49 9a [2] 0e 8b [2] 40 87 [2] 4c 8d [2] 5b 86 [2] 40 c8 [2] 7d }

  condition:
    any of them
}