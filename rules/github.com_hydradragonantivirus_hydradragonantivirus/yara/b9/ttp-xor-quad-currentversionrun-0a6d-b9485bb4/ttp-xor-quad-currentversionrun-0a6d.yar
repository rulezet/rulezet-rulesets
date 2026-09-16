rule TTP_XOR_QUAD_CurrentVersionRun_0a6d {
  strings:
    $key_0a6d = { 59 02 [2] 7d 0c [2] 56 20 [2] 78 02 [2] 6c 19 [2] 63 03 [2] 7d 1e [2] 7f 1f [2] 64 19 [2] 78 1e [2] 64 31 }

  condition:
    any of them
}