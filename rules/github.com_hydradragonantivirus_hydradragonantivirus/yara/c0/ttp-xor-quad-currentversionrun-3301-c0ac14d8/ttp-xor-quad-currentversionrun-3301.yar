rule TTP_XOR_QUAD_CurrentVersionRun_3301 {
  strings:
    $key_3301 = { 60 6e [2] 44 60 [2] 6f 4c [2] 41 6e [2] 55 75 [2] 5a 6f [2] 44 72 [2] 46 73 [2] 5d 75 [2] 41 72 [2] 5d 5d }

  condition:
    any of them
}