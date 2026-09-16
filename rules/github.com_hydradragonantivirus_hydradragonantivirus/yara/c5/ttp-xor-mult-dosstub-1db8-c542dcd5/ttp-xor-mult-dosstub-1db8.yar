rule TTP_XOR_MULT_DOSStub_1db8 {
  strings:
    $key_1db8 = { 49 d0 [2] 3d c8 [2] 7a ca [2] 3d db [2] 73 d7 [2] 7f dd [2] 68 d6 [2] 73 98 [2] 4e }

  condition:
    any of them
}