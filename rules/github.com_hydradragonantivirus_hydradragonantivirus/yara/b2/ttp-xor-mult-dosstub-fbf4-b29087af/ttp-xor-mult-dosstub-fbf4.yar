rule TTP_XOR_MULT_DOSStub_fbf4 {
  strings:
    $key_fbf4 = { af 9c [2] db 84 [2] 9c 86 [2] db 97 [2] 95 9b [2] 99 91 [2] 8e 9a [2] 95 d4 [2] a8 }

  condition:
    any of them
}