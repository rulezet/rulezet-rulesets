rule TTP_XOR_MULT_DOSStub_f6a2 {
  strings:
    $key_f6a2 = { a2 ca [2] d6 d2 [2] 91 d0 [2] d6 c1 [2] 98 cd [2] 94 c7 [2] 83 cc [2] 98 82 [2] a5 }

  condition:
    any of them
}