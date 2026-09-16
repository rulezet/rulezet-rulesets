rule TTP_XOR_MULT_DOSStub_2fa2 {
  strings:
    $key_2fa2 = { 7b ca [2] 0f d2 [2] 48 d0 [2] 0f c1 [2] 41 cd [2] 4d c7 [2] 5a cc [2] 41 82 [2] 7c }

  condition:
    any of them
}