rule TTP_XOR_QUAD_CurrentVersionRun_29f6 {
  strings:
    $key_29f6 = { 7a 99 [2] 5e 97 [2] 75 bb [2] 5b 99 [2] 4f 82 [2] 40 98 [2] 5e 85 [2] 5c 84 [2] 47 82 [2] 5b 85 [2] 47 aa }

  condition:
    any of them
}