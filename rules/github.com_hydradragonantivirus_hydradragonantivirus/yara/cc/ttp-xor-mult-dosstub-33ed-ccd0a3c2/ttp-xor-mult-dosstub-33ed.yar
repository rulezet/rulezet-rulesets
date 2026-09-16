rule TTP_XOR_MULT_DOSStub_33ed {
  strings:
    $key_33ed = { 67 85 [2] 13 9d [2] 54 9f [2] 13 8e [2] 5d 82 [2] 51 88 [2] 46 83 [2] 5d cd [2] 60 }

  condition:
    any of them
}