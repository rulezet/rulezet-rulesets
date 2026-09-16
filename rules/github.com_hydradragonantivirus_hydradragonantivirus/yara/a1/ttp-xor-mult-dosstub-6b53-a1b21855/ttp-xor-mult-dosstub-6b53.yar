rule TTP_XOR_MULT_DOSStub_6b53 {
  strings:
    $key_6b53 = { 3f 3b [2] 4b 23 [2] 0c 21 [2] 4b 30 [2] 05 3c [2] 09 36 [2] 1e 3d [2] 05 73 [2] 38 }

  condition:
    any of them
}