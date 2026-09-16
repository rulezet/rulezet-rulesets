rule TTP_XOR_QUAD_CurrentVersionRun_eb11 {
  strings:
    $key_eb11 = { b8 7e [2] 9c 70 [2] b7 5c [2] 99 7e [2] 8d 65 [2] 82 7f [2] 9c 62 [2] 9e 63 [2] 85 65 [2] 99 62 [2] 85 4d }

  condition:
    any of them
}