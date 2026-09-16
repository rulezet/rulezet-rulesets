rule TTP_XOR_QUAD_CurrentVersionRun_3d12 {
  strings:
    $key_3d12 = { 6e 7d [2] 4a 73 [2] 61 5f [2] 4f 7d [2] 5b 66 [2] 54 7c [2] 4a 61 [2] 48 60 [2] 53 66 [2] 4f 61 [2] 53 4e }

  condition:
    any of them
}