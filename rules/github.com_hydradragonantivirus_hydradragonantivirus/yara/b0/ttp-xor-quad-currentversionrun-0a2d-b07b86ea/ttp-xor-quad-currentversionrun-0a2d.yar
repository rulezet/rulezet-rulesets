rule TTP_XOR_QUAD_CurrentVersionRun_0a2d {
  strings:
    $key_0a2d = { 59 42 [2] 7d 4c [2] 56 60 [2] 78 42 [2] 6c 59 [2] 63 43 [2] 7d 5e [2] 7f 5f [2] 64 59 [2] 78 5e [2] 64 71 }

  condition:
    any of them
}