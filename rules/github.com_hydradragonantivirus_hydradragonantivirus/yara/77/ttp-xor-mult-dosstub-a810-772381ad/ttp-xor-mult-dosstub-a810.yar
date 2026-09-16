rule TTP_XOR_MULT_DOSStub_a810 {
  strings:
    $key_a810 = { fc 78 [2] 88 60 [2] cf 62 [2] 88 73 [2] c6 7f [2] ca 75 [2] dd 7e [2] c6 30 [2] fb }

  condition:
    any of them
}