rule TTP_XOR_QUAD_CurrentVersionRun_390a {
  strings:
    $key_390a = { 6a 65 [2] 4e 6b [2] 65 47 [2] 4b 65 [2] 5f 7e [2] 50 64 [2] 4e 79 [2] 4c 78 [2] 57 7e [2] 4b 79 [2] 57 56 }

  condition:
    any of them
}