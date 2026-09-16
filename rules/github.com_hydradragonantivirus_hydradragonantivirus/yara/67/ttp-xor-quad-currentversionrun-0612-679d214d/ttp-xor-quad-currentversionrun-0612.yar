rule TTP_XOR_QUAD_CurrentVersionRun_0612 {
  strings:
    $key_0612 = { 55 7d [2] 71 73 [2] 5a 5f [2] 74 7d [2] 60 66 [2] 6f 7c [2] 71 61 [2] 73 60 [2] 68 66 [2] 74 61 [2] 68 4e }

  condition:
    any of them
}