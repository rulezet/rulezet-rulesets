rule TTP_XOR_MULT_DOSStub_2eb8 {
  strings:
    $key_2eb8 = { 7a d0 [2] 0e c8 [2] 49 ca [2] 0e db [2] 40 d7 [2] 4c dd [2] 5b d6 [2] 40 98 [2] 7d }

  condition:
    any of them
}