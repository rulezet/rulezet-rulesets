rule TTP_XOR_MULT_DOSStub_01ed {
  strings:
    $key_01ed = { 55 85 [2] 21 9d [2] 66 9f [2] 21 8e [2] 6f 82 [2] 63 88 [2] 74 83 [2] 6f cd [2] 52 }

  condition:
    any of them
}