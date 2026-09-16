rule TTP_XOR_MULT_DOSStub_fbed {
  strings:
    $key_fbed = { af 85 [2] db 9d [2] 9c 9f [2] db 8e [2] 95 82 [2] 99 88 [2] 8e 83 [2] 95 cd [2] a8 }

  condition:
    any of them
}