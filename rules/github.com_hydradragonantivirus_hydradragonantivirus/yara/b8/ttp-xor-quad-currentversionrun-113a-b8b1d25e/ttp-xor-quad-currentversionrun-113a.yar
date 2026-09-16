rule TTP_XOR_QUAD_CurrentVersionRun_113a {
  strings:
    $key_113a = { 42 55 [2] 66 5b [2] 4d 77 [2] 63 55 [2] 77 4e [2] 78 54 [2] 66 49 [2] 64 48 [2] 7f 4e [2] 63 49 [2] 7f 66 }

  condition:
    any of them
}