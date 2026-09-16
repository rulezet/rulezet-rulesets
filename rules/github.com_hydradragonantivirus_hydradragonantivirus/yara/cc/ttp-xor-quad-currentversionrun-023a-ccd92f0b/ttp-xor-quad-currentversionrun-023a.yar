rule TTP_XOR_QUAD_CurrentVersionRun_023a {
  strings:
    $key_023a = { 51 55 [2] 75 5b [2] 5e 77 [2] 70 55 [2] 64 4e [2] 6b 54 [2] 75 49 [2] 77 48 [2] 6c 4e [2] 70 49 [2] 6c 66 }

  condition:
    any of them
}