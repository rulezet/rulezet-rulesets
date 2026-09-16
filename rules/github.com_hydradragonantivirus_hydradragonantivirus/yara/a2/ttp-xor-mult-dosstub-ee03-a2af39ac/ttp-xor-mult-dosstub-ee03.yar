rule TTP_XOR_MULT_DOSStub_ee03 {
  strings:
    $key_ee03 = { ba 6b [2] ce 73 [2] 89 71 [2] ce 60 [2] 80 6c [2] 8c 66 [2] 9b 6d [2] 80 23 [2] bd }

  condition:
    any of them
}