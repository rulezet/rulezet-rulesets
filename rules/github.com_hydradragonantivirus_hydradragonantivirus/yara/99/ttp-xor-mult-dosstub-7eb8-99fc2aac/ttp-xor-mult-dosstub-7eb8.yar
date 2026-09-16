rule TTP_XOR_MULT_DOSStub_7eb8 {
  strings:
    $key_7eb8 = { 2a d0 [2] 5e c8 [2] 19 ca [2] 5e db [2] 10 d7 [2] 1c dd [2] 0b d6 [2] 10 98 [2] 2d }

  condition:
    any of them
}