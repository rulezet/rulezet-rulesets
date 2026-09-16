rule TTP_XOR_MULT_DOSStub_0aed {
  strings:
    $key_0aed = { 5e 85 [2] 2a 9d [2] 6d 9f [2] 2a 8e [2] 64 82 [2] 68 88 [2] 7f 83 [2] 64 cd [2] 59 }

  condition:
    any of them
}