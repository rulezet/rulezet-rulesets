rule TTP_XOR_MULT_DOSStub_2724 {
  strings:
    $key_2724 = { 73 4c [2] 07 54 [2] 40 56 [2] 07 47 [2] 49 4b [2] 45 41 [2] 52 4a [2] 49 04 [2] 74 }

  condition:
    any of them
}