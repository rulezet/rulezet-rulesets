rule TTP_XOR_QUAD_CurrentVersionRun_1612 {
  strings:
    $key_1612 = { 45 7d [2] 61 73 [2] 4a 5f [2] 64 7d [2] 70 66 [2] 7f 7c [2] 61 61 [2] 63 60 [2] 78 66 [2] 64 61 [2] 78 4e }

  condition:
    any of them
}