rule TTP_XOR_QUAD_CurrentVersionRun_0a03 {
  strings:
    $key_0a03 = { 59 6c [2] 7d 62 [2] 56 4e [2] 78 6c [2] 6c 77 [2] 63 6d [2] 7d 70 [2] 7f 71 [2] 64 77 [2] 78 70 [2] 64 5f }

  condition:
    any of them
}