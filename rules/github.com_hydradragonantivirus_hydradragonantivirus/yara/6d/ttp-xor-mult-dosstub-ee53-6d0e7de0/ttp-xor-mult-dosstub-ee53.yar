rule TTP_XOR_MULT_DOSStub_ee53 {
  strings:
    $key_ee53 = { ba 3b [2] ce 23 [2] 89 21 [2] ce 30 [2] 80 3c [2] 8c 36 [2] 9b 3d [2] 80 73 [2] bd }

  condition:
    any of them
}