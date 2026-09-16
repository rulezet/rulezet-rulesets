rule TTP_XOR_MULT_DOSStub_2b29 {
  strings:
    $key_2b29 = { 7f 41 [2] 0b 59 [2] 4c 5b [2] 0b 4a [2] 45 46 [2] 49 4c [2] 5e 47 [2] 45 09 [2] 78 }

  condition:
    any of them
}