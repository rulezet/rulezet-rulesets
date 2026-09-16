rule TTP_XOR_QUAD_CurrentVersionRun_3249 {
  strings:
    $key_3249 = { 61 26 [2] 45 28 [2] 6e 04 [2] 40 26 [2] 54 3d [2] 5b 27 [2] 45 3a [2] 47 3b [2] 5c 3d [2] 40 3a [2] 5c 15 }

  condition:
    any of them
}