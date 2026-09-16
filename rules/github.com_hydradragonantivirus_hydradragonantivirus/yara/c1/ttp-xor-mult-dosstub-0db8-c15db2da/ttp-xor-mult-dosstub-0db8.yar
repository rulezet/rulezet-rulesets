rule TTP_XOR_MULT_DOSStub_0db8 {
  strings:
    $key_0db8 = { 59 d0 [2] 2d c8 [2] 6a ca [2] 2d db [2] 63 d7 [2] 6f dd [2] 78 d6 [2] 63 98 [2] 5e }

  condition:
    any of them
}