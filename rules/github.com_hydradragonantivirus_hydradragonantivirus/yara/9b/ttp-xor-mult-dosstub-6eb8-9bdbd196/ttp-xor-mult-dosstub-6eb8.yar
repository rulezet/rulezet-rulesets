rule TTP_XOR_MULT_DOSStub_6eb8 {
  strings:
    $key_6eb8 = { 3a d0 [2] 4e c8 [2] 09 ca [2] 4e db [2] 00 d7 [2] 0c dd [2] 1b d6 [2] 00 98 [2] 3d }

  condition:
    any of them
}