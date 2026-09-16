rule TTP_XOR_MULT_DOSStub_fb9f {
  strings:
    $key_fb9f = { af f7 [2] db ef [2] 9c ed [2] db fc [2] 95 f0 [2] 99 fa [2] 8e f1 [2] 95 bf [2] a8 }

  condition:
    any of them
}