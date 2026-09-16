rule TTP_XOR_MULT_DOSStub_ee14 {
  strings:
    $key_ee14 = { ba 7c [2] ce 64 [2] 89 66 [2] ce 77 [2] 80 7b [2] 8c 71 [2] 9b 7a [2] 80 34 [2] bd }

  condition:
    any of them
}