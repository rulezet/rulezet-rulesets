rule TTP_XOR_MULT_DOSStub_6db8 {
  strings:
    $key_6db8 = { 39 d0 [2] 4d c8 [2] 0a ca [2] 4d db [2] 03 d7 [2] 0f dd [2] 18 d6 [2] 03 98 [2] 3e }

  condition:
    any of them
}