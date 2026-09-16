rule TTP_XOR_QUAD_CurrentVersionRun_19f6 {
  strings:
    $key_19f6 = { 4a 99 [2] 6e 97 [2] 45 bb [2] 6b 99 [2] 7f 82 [2] 70 98 [2] 6e 85 [2] 6c 84 [2] 77 82 [2] 6b 85 [2] 77 aa }

  condition:
    any of them
}