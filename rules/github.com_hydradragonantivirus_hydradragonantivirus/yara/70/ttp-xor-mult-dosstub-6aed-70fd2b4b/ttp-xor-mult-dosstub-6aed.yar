rule TTP_XOR_MULT_DOSStub_6aed {
  strings:
    $key_6aed = { 3e 85 [2] 4a 9d [2] 0d 9f [2] 4a 8e [2] 04 82 [2] 08 88 [2] 1f 83 [2] 04 cd [2] 39 }

  condition:
    any of them
}