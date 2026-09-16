rule TTP_XOR_QUAD_CurrentVersionRun_14f3 {
  strings:
    $key_14f3 = { 47 9c [2] 63 92 [2] 48 be [2] 66 9c [2] 72 87 [2] 7d 9d [2] 63 80 [2] 61 81 [2] 7a 87 [2] 66 80 [2] 7a af }

  condition:
    any of them
}