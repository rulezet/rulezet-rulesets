rule TTP_XOR_MULT_DOSStub_672b {
  strings:
    $key_672b = { 33 43 [2] 47 5b [2] 00 59 [2] 47 48 [2] 09 44 [2] 05 4e [2] 12 45 [2] 09 0b [2] 34 }

  condition:
    any of them
}