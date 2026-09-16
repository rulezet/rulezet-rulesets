rule TTP_XOR_QUAD_CurrentVersionRun_0203 {
  strings:
    $key_0203 = { 51 6c [2] 75 62 [2] 5e 4e [2] 70 6c [2] 64 77 [2] 6b 6d [2] 75 70 [2] 77 71 [2] 6c 77 [2] 70 70 [2] 6c 5f }

  condition:
    any of them
}