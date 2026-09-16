rule TTP_XOR_MULT_DOSStub_3eb8 {
  strings:
    $key_3eb8 = { 6a d0 [2] 1e c8 [2] 59 ca [2] 1e db [2] 50 d7 [2] 5c dd [2] 4b d6 [2] 50 98 [2] 6d }

  condition:
    any of them
}