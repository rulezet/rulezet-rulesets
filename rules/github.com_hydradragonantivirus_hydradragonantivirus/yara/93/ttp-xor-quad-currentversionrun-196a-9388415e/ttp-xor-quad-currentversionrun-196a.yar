rule TTP_XOR_QUAD_CurrentVersionRun_196a {
  strings:
    $key_196a = { 4a 05 [2] 6e 0b [2] 45 27 [2] 6b 05 [2] 7f 1e [2] 70 04 [2] 6e 19 [2] 6c 18 [2] 77 1e [2] 6b 19 [2] 77 36 }

  condition:
    any of them
}