rule TTP_XOR_QUAD_CurrentVersionRun_faf6 {
  strings:
    $key_faf6 = { a9 99 [2] 8d 97 [2] a6 bb [2] 88 99 [2] 9c 82 [2] 93 98 [2] 8d 85 [2] 8f 84 [2] 94 82 [2] 88 85 [2] 94 aa }

  condition:
    any of them
}