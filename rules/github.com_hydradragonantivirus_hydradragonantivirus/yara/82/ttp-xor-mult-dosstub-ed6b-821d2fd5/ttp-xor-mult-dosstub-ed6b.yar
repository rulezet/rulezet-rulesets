rule TTP_XOR_MULT_DOSStub_ed6b {
  strings:
    $key_ed6b = { b9 03 [2] cd 1b [2] 8a 19 [2] cd 08 [2] 83 04 [2] 8f 0e [2] 98 05 [2] 83 4b [2] be }

  condition:
    any of them
}