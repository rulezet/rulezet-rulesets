rule TTP_XOR_QUAD_CurrentVersionRun_0af6 {
  strings:
    $key_0af6 = { 59 99 [2] 7d 97 [2] 56 bb [2] 78 99 [2] 6c 82 [2] 63 98 [2] 7d 85 [2] 7f 84 [2] 64 82 [2] 78 85 [2] 64 aa }

  condition:
    any of them
}