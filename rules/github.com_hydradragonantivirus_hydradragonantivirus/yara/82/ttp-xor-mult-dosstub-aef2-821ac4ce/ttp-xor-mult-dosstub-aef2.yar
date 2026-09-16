rule TTP_XOR_MULT_DOSStub_aef2 {
  strings:
    $key_aef2 = { fa 9a [2] 8e 82 [2] c9 80 [2] 8e 91 [2] c0 9d [2] cc 97 [2] db 9c [2] c0 d2 [2] fd }

  condition:
    any of them
}