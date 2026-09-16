rule TTP_XOR_MULT_DOSStub_bba8 {
  strings:
    $key_bba8 = { ef c0 [2] 9b d8 [2] dc da [2] 9b cb [2] d5 c7 [2] d9 cd [2] ce c6 [2] d5 88 [2] e8 }

  condition:
    any of them
}