rule TTP_XOR_QUAD_CurrentVersionRun_eb22 {
  strings:
    $key_eb22 = { b8 4d [2] 9c 43 [2] b7 6f [2] 99 4d [2] 8d 56 [2] 82 4c [2] 9c 51 [2] 9e 50 [2] 85 56 [2] 99 51 [2] 85 7e }

  condition:
    any of them
}