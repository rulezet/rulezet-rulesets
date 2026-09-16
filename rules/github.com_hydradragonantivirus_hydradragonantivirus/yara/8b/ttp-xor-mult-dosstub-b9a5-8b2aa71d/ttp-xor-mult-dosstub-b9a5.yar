rule TTP_XOR_MULT_DOSStub_b9a5 {
  strings:
    $key_b9a5 = { ed cd [2] 99 d5 [2] de d7 [2] 99 c6 [2] d7 ca [2] db c0 [2] cc cb [2] d7 85 [2] ea }

  condition:
    any of them
}