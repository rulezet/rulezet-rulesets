rule TTP_XOR_QUAD_CurrentVersionRun_03f6 {
  strings:
    $key_03f6 = { 50 99 [2] 74 97 [2] 5f bb [2] 71 99 [2] 65 82 [2] 6a 98 [2] 74 85 [2] 76 84 [2] 6d 82 [2] 71 85 [2] 6d aa }

  condition:
    any of them
}