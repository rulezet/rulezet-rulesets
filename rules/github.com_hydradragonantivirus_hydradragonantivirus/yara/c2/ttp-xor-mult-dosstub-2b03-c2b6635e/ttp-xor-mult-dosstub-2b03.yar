rule TTP_XOR_MULT_DOSStub_2b03 {
  strings:
    $key_2b03 = { 7f 6b [2] 0b 73 [2] 4c 71 [2] 0b 60 [2] 45 6c [2] 49 66 [2] 5e 6d [2] 45 23 [2] 78 }

  condition:
    any of them
}