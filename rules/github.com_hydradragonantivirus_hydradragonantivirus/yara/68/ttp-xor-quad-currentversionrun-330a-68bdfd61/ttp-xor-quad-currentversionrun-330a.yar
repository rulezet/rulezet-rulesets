rule TTP_XOR_QUAD_CurrentVersionRun_330a {
  strings:
    $key_330a = { 60 65 [2] 44 6b [2] 6f 47 [2] 41 65 [2] 55 7e [2] 5a 64 [2] 44 79 [2] 46 78 [2] 5d 7e [2] 41 79 [2] 5d 56 }

  condition:
    any of them
}