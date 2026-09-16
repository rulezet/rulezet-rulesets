rule TTP_XOR_MULT_DOSStub_fb63 {
  strings:
    $key_fb63 = { af 0b [2] db 13 [2] 9c 11 [2] db 00 [2] 95 0c [2] 99 06 [2] 8e 0d [2] 95 43 [2] a8 }

  condition:
    any of them
}