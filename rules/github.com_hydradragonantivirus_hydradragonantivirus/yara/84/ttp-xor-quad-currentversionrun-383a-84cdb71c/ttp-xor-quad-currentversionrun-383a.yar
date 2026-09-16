rule TTP_XOR_QUAD_CurrentVersionRun_383a {
  strings:
    $key_383a = { 6b 55 [2] 4f 5b [2] 64 77 [2] 4a 55 [2] 5e 4e [2] 51 54 [2] 4f 49 [2] 4d 48 [2] 56 4e [2] 4a 49 [2] 56 66 }

  condition:
    any of them
}