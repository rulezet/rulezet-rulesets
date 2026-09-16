rule TTP_XOR_QUAD_CurrentVersionRun_101b {
  strings:
    $key_101b = { 43 74 [2] 67 7a [2] 4c 56 [2] 62 74 [2] 76 6f [2] 79 75 [2] 67 68 [2] 65 69 [2] 7e 6f [2] 62 68 [2] 7e 47 }

  condition:
    any of them
}