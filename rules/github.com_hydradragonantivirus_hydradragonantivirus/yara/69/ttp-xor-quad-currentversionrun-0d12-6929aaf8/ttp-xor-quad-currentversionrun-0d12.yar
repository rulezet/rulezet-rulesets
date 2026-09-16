rule TTP_XOR_QUAD_CurrentVersionRun_0d12 {
  strings:
    $key_0d12 = { 5e 7d [2] 7a 73 [2] 51 5f [2] 7f 7d [2] 6b 66 [2] 64 7c [2] 7a 61 [2] 78 60 [2] 63 66 [2] 7f 61 [2] 63 4e }

  condition:
    any of them
}