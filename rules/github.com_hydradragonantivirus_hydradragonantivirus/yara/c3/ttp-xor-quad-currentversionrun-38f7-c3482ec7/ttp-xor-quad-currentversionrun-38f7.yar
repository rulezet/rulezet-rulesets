rule TTP_XOR_QUAD_CurrentVersionRun_38f7 {
  strings:
    $key_38f7 = { 6b 98 [2] 4f 96 [2] 64 ba [2] 4a 98 [2] 5e 83 [2] 51 99 [2] 4f 84 [2] 4d 85 [2] 56 83 [2] 4a 84 [2] 56 ab }

  condition:
    any of them
}