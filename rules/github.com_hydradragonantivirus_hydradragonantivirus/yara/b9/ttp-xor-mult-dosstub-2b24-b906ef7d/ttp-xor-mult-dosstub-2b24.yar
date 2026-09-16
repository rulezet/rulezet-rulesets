rule TTP_XOR_MULT_DOSStub_2b24 {
  strings:
    $key_2b24 = { 7f 4c [2] 0b 54 [2] 4c 56 [2] 0b 47 [2] 45 4b [2] 49 41 [2] 5e 4a [2] 45 04 [2] 78 }

  condition:
    any of them
}