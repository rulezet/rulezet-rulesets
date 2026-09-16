rule TTP_XOR_MULT_DOSStub_fea2 {
  strings:
    $key_fea2 = { aa ca [2] de d2 [2] 99 d0 [2] de c1 [2] 90 cd [2] 9c c7 [2] 8b cc [2] 90 82 [2] ad }

  condition:
    any of them
}