rule TTP_XOR_MULT_DOSStub_a86b {
  strings:
    $key_a86b = { fc 03 [2] 88 1b [2] cf 19 [2] 88 08 [2] c6 04 [2] ca 0e [2] dd 05 [2] c6 4b [2] fb }

  condition:
    any of them
}