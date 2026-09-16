rule TTP_XOR_QUAD_CurrentVersionRun_2712 {
  strings:
    $key_2712 = { 74 7d [2] 50 73 [2] 7b 5f [2] 55 7d [2] 41 66 [2] 4e 7c [2] 50 61 [2] 52 60 [2] 49 66 [2] 55 61 [2] 49 4e }

  condition:
    any of them
}