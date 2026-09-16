rule TTP_XOR_QUAD_CurrentVersionRun_eb32 {
  strings:
    $key_eb32 = { b8 5d [2] 9c 53 [2] b7 7f [2] 99 5d [2] 8d 46 [2] 82 5c [2] 9c 41 [2] 9e 40 [2] 85 46 [2] 99 41 [2] 85 6e }

  condition:
    any of them
}