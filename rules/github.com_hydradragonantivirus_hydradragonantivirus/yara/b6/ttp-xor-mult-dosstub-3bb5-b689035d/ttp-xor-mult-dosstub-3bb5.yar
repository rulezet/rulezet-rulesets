rule TTP_XOR_MULT_DOSStub_3bb5 {
  strings:
    $key_3bb5 = { 6f dd [2] 1b c5 [2] 5c c7 [2] 1b d6 [2] 55 da [2] 59 d0 [2] 4e db [2] 55 95 [2] 68 }

  condition:
    any of them
}