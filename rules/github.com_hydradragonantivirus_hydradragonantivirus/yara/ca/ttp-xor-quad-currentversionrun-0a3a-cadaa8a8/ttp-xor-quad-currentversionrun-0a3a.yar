rule TTP_XOR_QUAD_CurrentVersionRun_0a3a {
  strings:
    $key_0a3a = { 59 55 [2] 7d 5b [2] 56 77 [2] 78 55 [2] 6c 4e [2] 63 54 [2] 7d 49 [2] 7f 48 [2] 64 4e [2] 78 49 [2] 64 66 }

  condition:
    any of them
}