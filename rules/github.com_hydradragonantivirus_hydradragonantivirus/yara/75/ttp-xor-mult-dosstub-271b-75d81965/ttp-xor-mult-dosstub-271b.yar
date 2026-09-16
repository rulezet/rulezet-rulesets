rule TTP_XOR_MULT_DOSStub_271b {
  strings:
    $key_271b = { 73 73 [2] 07 6b [2] 40 69 [2] 07 78 [2] 49 74 [2] 45 7e [2] 52 75 [2] 49 3b [2] 74 }

  condition:
    any of them
}