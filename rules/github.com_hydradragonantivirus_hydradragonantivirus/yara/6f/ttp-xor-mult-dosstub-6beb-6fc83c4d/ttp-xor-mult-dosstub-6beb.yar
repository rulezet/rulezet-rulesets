rule TTP_XOR_MULT_DOSStub_6beb {
  strings:
    $key_6beb = { 3f 83 [2] 4b 9b [2] 0c 99 [2] 4b 88 [2] 05 84 [2] 09 8e [2] 1e 85 [2] 05 cb [2] 38 }

  condition:
    any of them
}