rule TTP_XOR_QUAD_CurrentVersionRun_eaea {
  strings:
    $key_eaea = { b9 85 [2] 9d 8b [2] b6 a7 [2] 98 85 [2] 8c 9e [2] 83 84 [2] 9d 99 [2] 9f 98 [2] 84 9e [2] 98 99 [2] 84 b6 }

  condition:
    any of them
}