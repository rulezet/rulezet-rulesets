rule TTP_XOR_MULT_DOSStub_2723 {
  strings:
    $key_2723 = { 73 4b [2] 07 53 [2] 40 51 [2] 07 40 [2] 49 4c [2] 45 46 [2] 52 4d [2] 49 03 [2] 74 }

  condition:
    any of them
}