rule TTP_XOR_QUAD_CurrentVersionRun_0a13 {
  strings:
    $key_0a13 = { 59 7c [2] 7d 72 [2] 56 5e [2] 78 7c [2] 6c 67 [2] 63 7d [2] 7d 60 [2] 7f 61 [2] 64 67 [2] 78 60 [2] 64 4f }

  condition:
    any of them
}