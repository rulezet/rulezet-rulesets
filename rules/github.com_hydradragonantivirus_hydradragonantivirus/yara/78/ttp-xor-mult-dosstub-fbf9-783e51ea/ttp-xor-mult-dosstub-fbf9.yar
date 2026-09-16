rule TTP_XOR_MULT_DOSStub_fbf9 {
  strings:
    $key_fbf9 = { af 91 [2] db 89 [2] 9c 8b [2] db 9a [2] 95 96 [2] 99 9c [2] 8e 97 [2] 95 d9 [2] a8 }

  condition:
    any of them
}