rule TTP_XOR_MULT_DOSStub_43ed {
  strings:
    $key_43ed = { 17 85 [2] 63 9d [2] 24 9f [2] 63 8e [2] 2d 82 [2] 21 88 [2] 36 83 [2] 2d cd [2] 10 }

  condition:
    any of them
}