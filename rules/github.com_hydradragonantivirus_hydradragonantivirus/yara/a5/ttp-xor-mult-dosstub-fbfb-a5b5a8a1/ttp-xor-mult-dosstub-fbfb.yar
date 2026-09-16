rule TTP_XOR_MULT_DOSStub_fbfb {
  strings:
    $key_fbfb = { af 93 [2] db 8b [2] 9c 89 [2] db 98 [2] 95 94 [2] 99 9e [2] 8e 95 [2] 95 db [2] a8 }

  condition:
    any of them
}