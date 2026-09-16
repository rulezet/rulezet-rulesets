rule TTP_XOR_MULT_DOSStub_19eb {
  strings:
    $key_19eb = { 4d 83 [2] 39 9b [2] 7e 99 [2] 39 88 [2] 77 84 [2] 7b 8e [2] 6c 85 [2] 77 cb [2] 4a }

  condition:
    any of them
}