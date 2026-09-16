rule TTP_XOR_MULT_DOSStub_fbf8 {
  strings:
    $key_fbf8 = { af 90 [2] db 88 [2] 9c 8a [2] db 9b [2] 95 97 [2] 99 9d [2] 8e 96 [2] 95 d8 [2] a8 }

  condition:
    any of them
}