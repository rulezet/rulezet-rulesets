rule TTP_XOR_MULT_DOSStub_eab8 {
  strings:
    $key_eab8 = { be d0 [2] ca c8 [2] 8d ca [2] ca db [2] 84 d7 [2] 88 dd [2] 9f d6 [2] 84 98 [2] b9 }

  condition:
    any of them
}