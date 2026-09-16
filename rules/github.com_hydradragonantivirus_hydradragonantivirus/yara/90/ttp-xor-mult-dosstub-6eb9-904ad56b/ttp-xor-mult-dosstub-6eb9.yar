rule TTP_XOR_MULT_DOSStub_6eb9 {
  strings:
    $key_6eb9 = { 3a d1 [2] 4e c9 [2] 09 cb [2] 4e da [2] 00 d6 [2] 0c dc [2] 1b d7 [2] 00 99 [2] 3d }

  condition:
    any of them
}