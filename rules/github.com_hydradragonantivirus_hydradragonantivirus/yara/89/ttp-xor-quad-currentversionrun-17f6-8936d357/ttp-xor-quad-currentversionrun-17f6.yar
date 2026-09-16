rule TTP_XOR_QUAD_CurrentVersionRun_17f6 {
  strings:
    $key_17f6 = { 44 99 [2] 60 97 [2] 4b bb [2] 65 99 [2] 71 82 [2] 7e 98 [2] 60 85 [2] 62 84 [2] 79 82 [2] 65 85 [2] 79 aa }

  condition:
    any of them
}