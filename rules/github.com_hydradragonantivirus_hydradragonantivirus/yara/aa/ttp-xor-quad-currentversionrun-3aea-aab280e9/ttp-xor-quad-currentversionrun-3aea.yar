rule TTP_XOR_QUAD_CurrentVersionRun_3aea {
  strings:
    $key_3aea = { 69 85 [2] 4d 8b [2] 66 a7 [2] 48 85 [2] 5c 9e [2] 53 84 [2] 4d 99 [2] 4f 98 [2] 54 9e [2] 48 99 [2] 54 b6 }

  condition:
    any of them
}