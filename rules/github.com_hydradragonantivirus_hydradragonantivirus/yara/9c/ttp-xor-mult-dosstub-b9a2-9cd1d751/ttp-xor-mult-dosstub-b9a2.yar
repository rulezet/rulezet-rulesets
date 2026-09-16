rule TTP_XOR_MULT_DOSStub_b9a2 {
  strings:
    $key_b9a2 = { ed ca [2] 99 d2 [2] de d0 [2] 99 c1 [2] d7 cd [2] db c7 [2] cc cc [2] d7 82 [2] ea }

  condition:
    any of them
}