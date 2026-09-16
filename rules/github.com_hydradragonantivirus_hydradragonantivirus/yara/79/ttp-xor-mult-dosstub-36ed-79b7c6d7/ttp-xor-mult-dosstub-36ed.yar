rule TTP_XOR_MULT_DOSStub_36ed {
  strings:
    $key_36ed = { 62 85 [2] 16 9d [2] 51 9f [2] 16 8e [2] 58 82 [2] 54 88 [2] 43 83 [2] 58 cd [2] 65 }

  condition:
    any of them
}