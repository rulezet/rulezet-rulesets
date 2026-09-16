rule TTP_XOR_MULT_DOSStub_13fd {
  strings:
    $key_13fd = { 47 95 [2] 33 8d [2] 74 8f [2] 33 9e [2] 7d 92 [2] 71 98 [2] 66 93 [2] 7d dd [2] 40 }

  condition:
    any of them
}