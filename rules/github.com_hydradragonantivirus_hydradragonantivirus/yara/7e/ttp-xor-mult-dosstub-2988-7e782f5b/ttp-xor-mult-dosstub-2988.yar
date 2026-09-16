rule TTP_XOR_MULT_DOSStub_2988 {
  strings:
    $key_2988 = { 7d e0 [2] 09 f8 [2] 4e fa [2] 09 eb [2] 47 e7 [2] 4b ed [2] 5c e6 [2] 47 a8 [2] 7a }

  condition:
    any of them
}