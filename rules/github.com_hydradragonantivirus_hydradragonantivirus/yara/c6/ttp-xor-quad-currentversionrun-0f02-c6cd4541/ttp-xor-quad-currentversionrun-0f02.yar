rule TTP_XOR_QUAD_CurrentVersionRun_0f02 {
  strings:
    $key_0f02 = { 5c 6d [2] 78 63 [2] 53 4f [2] 7d 6d [2] 69 76 [2] 66 6c [2] 78 71 [2] 7a 70 [2] 61 76 [2] 7d 71 [2] 61 5e }

  condition:
    any of them
}