rule TTP_XOR_MULT_DOSStub_6512 {
  strings:
    $key_6512 = { 31 7a [2] 45 62 [2] 02 60 [2] 45 71 [2] 0b 7d [2] 07 77 [2] 10 7c [2] 0b 32 [2] 36 }

  condition:
    any of them
}