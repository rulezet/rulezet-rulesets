rule TTP_XOR_MULT_DOSStub_5eb8 {
  strings:
    $key_5eb8 = { 0a d0 [2] 7e c8 [2] 39 ca [2] 7e db [2] 30 d7 [2] 3c dd [2] 2b d6 [2] 30 98 [2] 0d }

  condition:
    any of them
}