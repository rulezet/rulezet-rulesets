rule TTP_XOR_QUAD_CurrentVersionRun_0a33 {
  strings:
    $key_0a33 = { 59 5c [2] 7d 52 [2] 56 7e [2] 78 5c [2] 6c 47 [2] 63 5d [2] 7d 40 [2] 7f 41 [2] 64 47 [2] 78 40 [2] 64 6f }

  condition:
    any of them
}