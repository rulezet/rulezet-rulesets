rule TTP_XOR_MULT_DOSStub_09ba {
  strings:
    $key_09ba = { 5d d2 [2] 29 ca [2] 6e c8 [2] 29 d9 [2] 67 d5 [2] 6b df [2] 7c d4 [2] 67 9a [2] 5a }

  condition:
    any of them
}