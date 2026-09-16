rule TTP_XOR_QUAD_CurrentVersionRun_0a1f {
  strings:
    $key_0a1f = { 59 70 [2] 7d 7e [2] 56 52 [2] 78 70 [2] 6c 6b [2] 63 71 [2] 7d 6c [2] 7f 6d [2] 64 6b [2] 78 6c [2] 64 43 }

  condition:
    any of them
}