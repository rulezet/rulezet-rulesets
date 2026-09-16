rule TTP_XOR_QUAD_CurrentVersionRun_0f4f {
  strings:
    $key_0f4f = { 5c 20 [2] 78 2e [2] 53 02 [2] 7d 20 [2] 69 3b [2] 66 21 [2] 78 3c [2] 7a 3d [2] 61 3b [2] 7d 3c [2] 61 13 }

  condition:
    any of them
}