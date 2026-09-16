rule TTP_XOR_QUAD_CurrentVersionRun_e5f7 {
  strings:
    $key_e5f7 = { b6 98 [2] 92 96 [2] b9 ba [2] 97 98 [2] 83 83 [2] 8c 99 [2] 92 84 [2] 90 85 [2] 8b 83 [2] 97 84 [2] 8b ab }

  condition:
    any of them
}