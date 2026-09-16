rule TTP_XOR_QUAD_CurrentVersionRun_19f7 {
  strings:
    $key_19f7 = { 4a 98 [2] 6e 96 [2] 45 ba [2] 6b 98 [2] 7f 83 [2] 70 99 [2] 6e 84 [2] 6c 85 [2] 77 83 [2] 6b 84 [2] 77 ab }

  condition:
    any of them
}